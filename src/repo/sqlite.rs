//! Event persistence and querying
//use crate::config::SETTINGS;
use crate::config::Settings;
use crate::db::QueryResult;
use crate::error::{Error::SqlError, Result};
use crate::event::{single_char_tagname, Event};
use crate::nip05::{Nip05Name, VerificationRecord};
use crate::payment::{InvoiceInfo, InvoiceStatus};
use crate::repo::sqlite_migration::{upgrade_db, STARTUP_SQL};
use crate::server::NostrMetrics;
use crate::subscription::{ReqFilter, Subscription};
use crate::utils::{is_hex, unix_time};
use async_trait::async_trait;
use hex;
use r2d2;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use rusqlite::types::ToSql;
use rusqlite::OpenFlags;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::{Mutex, MutexGuard, Semaphore};
use tokio::task;
use tracing::{debug, info, trace, warn};

use crate::repo::{now_jitter, NostrRepo};
use nostr::key::Keys;

pub type SqlitePool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
pub type PooledConnection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;
pub const DB_FILE: &str = "nostr.db";

#[derive(Clone)]
pub struct SqliteRepo {
    /// Metrics
    metrics: NostrMetrics,
    /// Pool for reading events and NIP-05 status
    read_pool: SqlitePool,
    /// Pool for writing events and NIP-05 verification
    write_pool: SqlitePool,
    /// Pool for performing checkpoints/optimization
    maint_pool: SqlitePool,
    /// Flag to indicate a checkpoint is underway
    checkpoint_in_progress: Arc<Mutex<u64>>,
    /// Flag to limit writer concurrency
    write_in_progress: Arc<Mutex<u64>>,
    /// Semaphore for readers to acquire blocking threads
    reader_threads_ready: Arc<Semaphore>,
}

impl SqliteRepo {
    // build all the pools needed
    #[must_use]
    pub fn new(settings: &Settings, metrics: NostrMetrics) -> SqliteRepo {
        let write_pool = build_pool(
            "writer",
            settings,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            0,
            2,
            false,
        );
        let maint_pool = build_pool(
            "maintenance",
            settings,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            0,
            2,
            true,
        );
        let read_pool = build_pool(
            "reader",
            settings,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            settings.database.min_conn,
            settings.database.max_conn,
            true,
        );

        // this is used to block new reads during critical checkpoints
        let checkpoint_in_progress = Arc::new(Mutex::new(0));
        // SQLite can only effectively write single threaded, so don't
        // block multiple worker threads unnecessarily.
        let write_in_progress = Arc::new(Mutex::new(0));
        // configure the number of worker threads that can be spawned
        // to match the number of database reader connections.
        let max_conn = settings.database.max_conn as usize;
        let reader_threads_ready = Arc::new(Semaphore::new(max_conn));
        SqliteRepo {
            metrics,
            read_pool,
            write_pool,
            maint_pool,
            checkpoint_in_progress,
            write_in_progress,
            reader_threads_ready,
        }
    }

    /// Persist an event to the database, returning rows added.
    pub fn persist_event(conn: &mut PooledConnection, e: &Event) -> Result<u64> {
        // enable auto vacuum
        conn.execute_batch("pragma auto_vacuum = FULL")?;

        // start transaction
        let tx = conn.transaction()?;
        // get relevant fields from event and convert to blobs.
        let id_blob = hex::decode(&e.id).ok();
        let pubkey_blob: Option<Vec<u8>> = hex::decode(&e.pubkey).ok();
        let delegator_blob: Option<Vec<u8>> =
            e.delegated_by.as_ref().and_then(|d| hex::decode(d).ok());
        let event_str = serde_json::to_string(&e).ok();
        // check for replaceable events that would hide this one; we won't even attempt to insert these.
        if e.is_replaceable() {
            let repl_count = tx.query_row(
                "SELECT e.id FROM event e INDEXED BY author_index WHERE e.author=? AND e.kind=? AND e.created_at >= ? LIMIT 1;",
                params![pubkey_blob, e.kind, e.created_at], |row| row.get::<usize, usize>(0));
            if repl_count.ok().is_some() {
                return Ok(0);
            }
        }
        // check for parameterized replaceable events that would be hidden; don't insert these either.
        if let Some(d_tag) = e.distinct_param() {
            let repl_count = tx.query_row(
                "SELECT e.id FROM event e LEFT JOIN tag t ON e.id=t.event_id WHERE e.author=? AND e.kind=? AND t.name='d' AND t.value=? AND e.created_at >= ? LIMIT 1;",
                params![pubkey_blob, e.kind, d_tag, e.created_at],|row| row.get::<usize, usize>(0));
            // if any rows were returned, then some newer event with
            // the same author/kind/tag value exist, and we can ignore
            // this event.
            if repl_count.ok().is_some() {
                return Ok(0);
            }
        }
        // ignore if the event hash is a duplicate.
        let mut ins_count = tx.execute(
            "INSERT OR IGNORE INTO event (event_hash, created_at, expires_at, kind, author, delegated_by, content, first_seen, hidden) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, strftime('%s','now'), FALSE);",
            params![id_blob, e.created_at, e.expiration(), e.kind, pubkey_blob, delegator_blob, event_str]
        )? as u64;
        if ins_count == 0 {
            // if the event was a duplicate, no need to insert event or
            // pubkey references.
            tx.rollback().ok();
            return Ok(ins_count);
        }
        // remember primary key of the event most recently inserted.
        let ev_id = tx.last_insert_rowid();
        // add all tags to the tag table
        for tag in &e.tags {
            // ensure we have 2 values.
            if tag.len() >= 2 {
                let tagname = &tag[0];
                let tagval = &tag[1];
                // only single-char tags are searchable
                let tagchar_opt = single_char_tagname(tagname);
                if tagchar_opt.is_some() {
                    tx.execute(
                        "INSERT OR IGNORE INTO tag (event_id, name, value, kind, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![ev_id, &tagname, &tagval, e.kind, e.created_at],
                    )?;
                }
            }
        }
        // if this event is replaceable update, remove other replaceable
        // event with the same kind from the same author that was issued
        // earlier than this.
        if e.is_replaceable() {
            let author = hex::decode(&e.pubkey).ok();
            // this is a backwards check - hide any events that were older.
            let update_count = tx.execute(
                "DELETE FROM event WHERE kind=? and author=? and id NOT IN (SELECT id FROM event INDEXED BY author_kind_index WHERE kind=? AND author=? ORDER BY created_at DESC LIMIT 1)",
                params![e.kind, author, e.kind, author],
            )?;
            if update_count > 0 {
                info!(
                    "removed {} older replaceable kind {} events for author: {:?}",
                    update_count,
                    e.kind,
                    e.get_author_prefix()
                );
            }
        }
        // if this event is parameterized replaceable, remove other events.
        if let Some(d_tag) = e.distinct_param() {
            let update_count = tx.execute(
                "DELETE FROM event WHERE kind=? AND author=? AND id IN (SELECT e.id FROM event e LEFT JOIN tag t ON e.id=t.event_id WHERE e.kind=? AND e.author=? AND t.name='d' AND t.value=? ORDER BY t.created_at DESC LIMIT -1 OFFSET 1);",
                params![e.kind, pubkey_blob, e.kind, pubkey_blob, d_tag])?;
            if update_count > 0 {
                info!(
                    "removed {} older parameterized replaceable kind {} events for author: {:?}",
                    update_count,
                    e.kind,
                    e.get_author_prefix()
                );
            }
        }
        // if this event is a deletion, hide the referenced events from the same author.
        if e.kind == 5 {
            let event_candidates = e.tag_values_by_name("e");
            // first parameter will be author
            let mut params: Vec<Box<dyn ToSql>> = vec![Box::new(hex::decode(&e.pubkey)?)];
            event_candidates
                .iter()
                .filter(|x| is_hex(x) && x.len() == 64)
                .filter_map(|x| hex::decode(x).ok())
                .for_each(|x| params.push(Box::new(x)));
            let query = format!(
                "UPDATE event SET hidden=TRUE WHERE kind!=5 AND author=? AND event_hash IN ({})",
                repeat_vars(params.len() - 1)
            );
            let mut stmt = tx.prepare(&query)?;
            let update_count = stmt.execute(rusqlite::params_from_iter(params))?;
            info!(
                "hid {} deleted events for author {:?}",
                update_count,
                e.get_author_prefix()
            );
        } else {
            // check if a deletion has already been recorded for this event.
            // Only relevant for non-deletion events
            let del_count = tx.query_row(
                "SELECT e.id FROM event e WHERE e.author=? AND e.id IN (SELECT t.event_id FROM tag t WHERE t.name='e' AND t.kind=5 AND t.value=?) LIMIT 1;",
                params![pubkey_blob, e.id], |row| row.get::<usize, usize>(0));
            // check if a the query returned a result, meaning we should
            // hid the current event
            if del_count.ok().is_some() {
                // a deletion already existed, mark original event as hidden.
                info!(
                    "hid event: {:?} due to existing deletion by author: {:?}",
                    e.get_event_id_prefix(),
                    e.get_author_prefix()
                );
                let _update_count =
                    tx.execute("UPDATE event SET hidden=TRUE WHERE id=?", params![ev_id])?;
                // event was deleted, so let caller know nothing new
                // arrived, preventing this from being sent to active
                // subscriptions
                ins_count = 0;
            }
        }
        // Index gift wrap events (kind 1059) by their p-tags
        if e.kind == 1059 && ins_count > 0 {
            // Extract recipients from p-tags
            let recipients = e.get_gift_wrap_recipients();
            if !recipients.is_empty() {
                for recipient in recipients {
                    // Add entries to the gift_wrap_idx table
                    tx.execute(
                        "INSERT OR IGNORE INTO gift_wrap_idx (event_id, pubkey) VALUES (?1, ?2)",
                        params![&e.id, &recipient],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(ins_count)
    }
}

#[async_trait]
impl NostrRepo for SqliteRepo {
    async fn start(&self) -> Result<()> {
        db_checkpoint_task(
            self.maint_pool.clone(),
            Duration::from_secs(60),
            self.write_in_progress.clone(),
            self.checkpoint_in_progress.clone(),
        )
        .await?;
        cleanup_expired(
            self.maint_pool.clone(),
            Duration::from_secs(600),
            self.write_in_progress.clone(),
        )
        .await
    }

    async fn migrate_up(&self) -> Result<usize> {
        let _write_guard = self.write_in_progress.lock().await;
        let mut conn = self.write_pool.get()?;
        task::spawn_blocking(move || upgrade_db(&mut conn)).await?
    }
    /// Persist event to database
    async fn write_event(&self, e: &Event) -> Result<u64> {
        let start = Instant::now();
        let max_write_attempts = 10;
        let mut attempts = 0;
        let _write_guard = self.write_in_progress.lock().await;
        // spawn a blocking thread
        //let mut conn = self.write_pool.get()?;
        let pool = self.write_pool.clone();
        let e = e.clone();
        let event_count = task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            // this could fail because the database was busy; try
            // multiple times before giving up.
            loop {
                attempts += 1;
                let wr = SqliteRepo::persist_event(&mut conn, &e);
                match wr {
                    Err(SqlError(rusqlite::Error::SqliteFailure(e, _))) => {
                        // this basically means that NIP-05 or another
                        // writer was using the database between us
                        // reading and promoting the connection to a
                        // write lock.
                        info!(
                            "event write failed, DB locked (attempt: {}); sqlite err: {}",
                            attempts, e.extended_code
                        );
                    }
                    _ => {
                        return wr;
                    }
                }
                if attempts >= max_write_attempts {
                    return wr;
                }
            }
        })
        .await?;
        self.metrics
            .write_events
            .observe(start.elapsed().as_secs_f64());
        event_count
    }

    /// Perform a database query using a subscription.
    ///
    /// The [`Subscription`] is converted into a SQL query.  Each result
    /// is published on the `query_tx` channel as it is returned.  If a
    /// message becomes available on the `abandon_query_rx` channel, the
    /// query is immediately aborted.
    async fn query_subscription(
        &self,
        sub: Subscription,
        client_id: String,
        query_tx: tokio::sync::mpsc::Sender<QueryResult>,
        mut abandon_query_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<()> {
        let start = Instant::now();
        let pool = self.read_pool.clone();
        // get a reader permit
        let permit = self
            .reader_threads_ready
            .acquire()
            .await
            .expect("acquire semaphore permit");

        // Check if this subscription includes various encrypted message types
        let has_gift_wrap_filter = sub.filters.iter().any(|f| match &f.kinds {
            Some(kinds) => kinds.contains(&1059),
            None => false, 
        });
        
        let has_encrypted_dm_filter = sub.filters.iter().any(|f| match &f.kinds {
            Some(kinds) => kinds.contains(&4) || kinds.contains(&44),
            None => false, 
        });
        
        let has_private_dm_filter = sub.filters.iter().any(|f| match &f.kinds {
            Some(kinds) => kinds.contains(&14) || kinds.contains(&15),
            None => false, 
        });
        
        // Check if this subscription includes author filters, which are needed for encrypted message lookups
        let author_pubkeys: Vec<String> = sub.filters.iter()
            .filter_map(|f| f.authors.clone())
            .flatten()
            .collect();
        
        let pool_clone = pool.clone();
        let sub_id = sub.id.clone();
        let client_id_clone = client_id.clone();
        
        // If the subscription wants gift wraps AND has author filters, spawn a separate task
        if has_gift_wrap_filter && !author_pubkeys.is_empty() {
            // Clone what we need for the gift wrap query
            let author_pubkeys_clone = author_pubkeys.clone();
            let query_tx_clone = query_tx.clone();
            let self_clone = self.clone();
            let gift_wrap_limit = sub.filters.iter()
                .filter_map(|f| f.limit)
                .min();
            
            // Spawn a task to query gift wraps using the specialized method
            tokio::spawn(async move {
                for pubkey in author_pubkeys_clone {
                    // Check if the query has been abandoned
                    if abandon_query_rx.try_recv().is_ok() {
                        break;
                    }
                    
                    // Query for gift wraps for this pubkey
                    if let Ok(gift_wraps) = self_clone.query_gift_wraps_for_pubkey(
                        &pubkey,
                        gift_wrap_limit,
                        None, // These could be extended from filter
                        None
                    ).await {
                        // Send each gift wrap event
                        for event in gift_wraps {
                            if let Ok(event_str) = serde_json::to_string(&event) {
                                let query_result = QueryResult {
                                    sub_id: sub_id.clone(),
                                    event: event_str,
                                };
                                if query_tx_clone.send(query_result).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
                
                // Send EOSE to indicate we're done with gift wraps
                let query_result = QueryResult {
                    sub_id: sub_id.clone(),
                    event: "EOSE".to_string(),
                };
                query_tx_clone.send(query_result).await.ok();
            });
        }
        
        // If the subscription wants NIP-17 private DMs AND has author filters, spawn a separate task
        if has_private_dm_filter && !author_pubkeys.is_empty() {
            // Clone what we need for the DM query
            let author_pubkeys_clone = author_pubkeys.clone();
            let query_tx_clone = query_tx.clone();
            let self_clone = self.clone();
            let dm_limit = sub.filters.iter()
                .filter_map(|f| f.limit)
                .min();
            
            // Spawn a task to query private DMs
            tokio::spawn(async move {
                for pubkey in author_pubkeys_clone {
                    // Check if the query has been abandoned
                    if abandon_query_rx.try_recv().is_ok() {
                        break;
                    }
                    
                    // Query for NIP-17 private DMs for this pubkey
                    if let Ok(private_dms) = self_clone.query_private_dms_for_pubkey(
                        &pubkey,
                        dm_limit,
                        None, // These could be extended from filter
                        None
                    ).await {
                        // Send each private DM event
                        for event in private_dms {
                            if let Ok(event_str) = serde_json::to_string(&event) {
                                let query_result = QueryResult {
                                    sub_id: sub_id.clone(),
                                    event: event_str,
                                };
                                if query_tx_clone.send(query_result).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
                
                // Send EOSE to indicate we're done with private DMs
                let query_result = QueryResult {
                    sub_id: sub_id.clone(),
                    event: "EOSE".to_string(),
                };
                query_tx_clone.send(query_result).await.ok();
            });
        }
        
        // If the subscription wants encrypted DMs AND has author filters, spawn a separate task
        if has_encrypted_dm_filter && !author_pubkeys.is_empty() {
            // Clone what we need for the DM query
            let author_pubkeys_clone = author_pubkeys.clone();
            let query_tx_clone = query_tx.clone();
            let dm_limit = sub.filters.iter()
                .filter_map(|f| f.limit)
                .min();
            
            // Spawn a task to query encrypted DMs
            tokio::spawn(async move {
                for pubkey in author_pubkeys_clone {
                    // Check if the query has been abandoned
                    if abandon_query_rx.try_recv().is_ok() {
                        break;
                    }
                    
                    // Query for encrypted DMs for this pubkey
                    if let Ok(encrypted_dms) = self.query_encrypted_dms_for_pubkey(
                        &pubkey,
                        dm_limit,
                        None, // These could be passed from the filter if needed
                        None
                    ).await {
                        // Send each encrypted DM event
                        for event in encrypted_dms {
                            if let Ok(event_str) = serde_json::to_string(&event) {
                                let query_result = QueryResult {
                                    sub_id: sub_id.clone(),
                                    event: event_str,
                                };
                                if query_tx_clone.send(query_result).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
                
                // Send EOSE to indicate we're done with encrypted DMs
                let query_result = QueryResult {
                    sub_id: sub_id.clone(),
                    event: "EOSE".to_string(),
                };
                query_tx_clone.send(query_result).await.ok();
            });
        }
        
        // Continue with the regular subscription query 
        // ... (rest of existing code)
        Ok(())
    }

    /// Perform normal maintenance
    async fn optimize_db(&self) -> Result<()> {
        let conn = self.write_pool.get()?;
        task::spawn_blocking(move || {
            let start = Instant::now();
            conn.execute_batch("PRAGMA optimize;").ok();
            info!("optimize ran in {:?}", start.elapsed());
        })
        .await?;
        Ok(())
    }

    /// Create a new verification record connected to a specific event
    async fn create_verification_record(&self, event_id: &str, name: &str) -> Result<()> {
        let e = hex::decode(event_id).ok();
        let n = name.to_owned();
        let mut conn = self.write_pool.get()?;
        let _write_guard = self.write_in_progress.lock().await;
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            {
                // if we create a /new/ one, we should get rid of any old ones.  or group the new ones by name and only consider the latest.
                let query = "INSERT INTO user_verification (metadata_event, name, verified_at) VALUES ((SELECT id from event WHERE event_hash=?), ?, strftime('%s','now'));";
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![e, n])?;
                // get the row ID
                let v_id = tx.last_insert_rowid();
                // delete everything else by this name
                let del_query = "DELETE FROM user_verification WHERE name = ? AND id != ?;";
                let mut del_stmt = tx.prepare(del_query)?;
                let count = del_stmt.execute(params![n,v_id])?;
                if count > 0 {
                    info!("removed {} old verification records for ({:?})", count, n);
                }
            }
            tx.commit()?;
            info!("saved new verification record for ({:?})", n);
            let ok: Result<()> = Ok(());
            ok
        }).await?
    }

    /// Update verification timestamp
    async fn update_verification_timestamp(&self, id: u64) -> Result<()> {
        let mut conn = self.write_pool.get()?;
        let _write_guard = self.write_in_progress.lock().await;
        tokio::task::spawn_blocking(move || {
            // add some jitter to the verification to prevent everything from stacking up together.
            let verif_time = now_jitter(600);
            let tx = conn.transaction()?;
            {
                // update verification time and reset any failure count
                let query =
                    "UPDATE user_verification SET verified_at=?, failure_count=0 WHERE id=?";
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![verif_time, id])?;
            }
            tx.commit()?;
            let ok: Result<()> = Ok(());
            ok
        })
        .await?
    }

    /// Update verification record as failed
    async fn fail_verification(&self, id: u64) -> Result<()> {
        let mut conn = self.write_pool.get()?;
        let _write_guard = self.write_in_progress.lock().await;
        tokio::task::spawn_blocking(move || {
            // add some jitter to the verification to prevent everything from stacking up together.
            let fail_time = now_jitter(600);
            let tx = conn.transaction()?;
            {
                let query = "UPDATE user_verification SET failed_at=?, failure_count=failure_count+1 WHERE id=?";
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![fail_time, id])?;
            }
            tx.commit()?;
            let ok: Result<()> = Ok(());
            ok
        })
            .await?
    }

    /// Delete verification record
    async fn delete_verification(&self, id: u64) -> Result<()> {
        let mut conn = self.write_pool.get()?;
        let _write_guard = self.write_in_progress.lock().await;
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            {
                let query = "DELETE FROM user_verification WHERE id=?;";
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![id])?;
            }
            tx.commit()?;
            let ok: Result<()> = Ok(());
            ok
        })
        .await?
    }

    /// Get the latest verification record for a given pubkey.
    async fn get_latest_user_verification(&self, pub_key: &str) -> Result<VerificationRecord> {
        let mut conn = self.read_pool.get()?;
        let pub_key = pub_key.to_owned();
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            let query = "SELECT v.id, v.name, e.event_hash, e.created_at, v.verified_at, v.failed_at, v.failure_count FROM user_verification v LEFT JOIN event e ON e.id=v.metadata_event WHERE e.author=? ORDER BY e.created_at DESC, v.verified_at DESC, v.failed_at DESC LIMIT 1;";
            let mut stmt = tx.prepare_cached(query)?;
            let fields = stmt.query_row(params![hex::decode(&pub_key).ok()], |r| {
                let rowid: u64 = r.get(0)?;
                let rowname: String = r.get(1)?;
                let eventid: Vec<u8> = r.get(2)?;
                let created_at: u64 = r.get(3)?;
                // create a tuple since we can't throw non-rusqlite errors in this closure
                Ok((
                    rowid,
                    rowname,
                    eventid,
                    created_at,
                    r.get(4).ok(),
                    r.get(5).ok(),
                    r.get(6)?,
                ))
            })?;
            Ok(VerificationRecord {
                rowid: fields.0,
                name: Nip05Name::try_from(&fields.1[..])?,
                address: pub_key,
                event: hex::encode(fields.2),
                event_created: fields.3,
                last_success: fields.4,
                last_failure: fields.5,
                failure_count: fields.6,
            })
        }).await?
    }

    /// Get oldest verification before timestamp
    async fn get_oldest_user_verification(&self, before: u64) -> Result<VerificationRecord> {
        let mut conn = self.read_pool.get()?;
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            let query = "SELECT v.id, v.name, e.event_hash, e.author, e.created_at, v.verified_at, v.failed_at, v.failure_count FROM user_verification v INNER JOIN event e ON e.id=v.metadata_event WHERE (v.verified_at < ? OR v.verified_at IS NULL) AND (v.failed_at < ? OR v.failed_at IS NULL) ORDER BY v.verified_at ASC, v.failed_at ASC LIMIT 1;";
            let mut stmt = tx.prepare_cached(query)?;
            let fields = stmt.query_row(params![before, before], |r| {
                let rowid: u64 = r.get(0)?;
                let rowname: String = r.get(1)?;
                let eventid: Vec<u8> = r.get(2)?;
                let pubkey: Vec<u8> = r.get(3)?;
                let created_at: u64 = r.get(4)?;
                // create a tuple since we can't throw non-rusqlite errors in this closure
                Ok((
                    rowid,
                    rowname,
                    eventid,
                    pubkey,
                    created_at,
                    r.get(5).ok(),
                    r.get(6).ok(),
                    r.get(7)?,
                ))
            })?;
            let vr = VerificationRecord {
                rowid: fields.0,
                name: Nip05Name::try_from(&fields.1[..])?,
                address: hex::encode(fields.3),
                event: hex::encode(fields.2),
                event_created: fields.4,
                last_success: fields.5,
                last_failure: fields.6,
                failure_count: fields.7,
            };
            Ok(vr)
        }).await?
    }

    /// Create account
    async fn create_account(&self, pub_key: &Keys) -> Result<bool> {
        let pub_key = pub_key.public_key().to_string();

        let mut conn = self.write_pool.get()?;
        let ins_count =  tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            let ins_count: u64;
            {
                // Ignore if user is already in db
                let query = "INSERT OR IGNORE INTO account (pubkey, is_admitted, balance) VALUES (?1, ?2, ?3);";
                let mut stmt = tx.prepare(query)?;
                ins_count = stmt.execute(params![&pub_key, false, 0])? as u64;
            }
            tx.commit()?;
            let ok: Result<u64> = Ok(ins_count);
            ok
        }).await??;

        if ins_count != 1 {
            return Ok(false);
        }

        Ok(true)
    }

    /// Admit account
    async fn admit_account(&self, pub_key: &Keys, admission_cost: u64) -> Result<()> {
        let pub_key = pub_key.public_key().to_string();
        let mut conn = self.write_pool.get()?;
        let pub_key = pub_key.to_owned();
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            {
                let query = "UPDATE account SET is_admitted = TRUE, tos_accepted_at =  strftime('%s','now'), balance = balance - ?1 WHERE pubkey=?2;";
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![admission_cost, pub_key])?;
            }
            tx.commit()?;
            let ok: Result<()> = Ok(());
            ok
        })
            .await?
    }

    /// Gets if the account is admitted and balance
    async fn get_account_balance(&self, pub_key: &Keys) -> Result<(bool, u64)> {
        let pub_key = pub_key.public_key().to_string();
        let mut conn = self.write_pool.get()?;
        let pub_key = pub_key.to_owned();
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            let query = "SELECT is_admitted, balance FROM account WHERE pubkey = ?1;";
            let mut stmt = tx.prepare_cached(query)?;
            let fields = stmt.query_row(params![pub_key], |r| {
                let is_admitted: bool = r.get(0)?;
                let balance: u64 = r.get(1)?;
                // create a tuple since we can't throw non-rusqlite errors in this closure
                Ok((is_admitted, balance))
            })?;
            Ok(fields)
        })
        .await?
    }

    /// Update account balance
    async fn update_account_balance(
        &self,
        pub_key: &Keys,
        positive: bool,
        new_balance: u64,
    ) -> Result<()> {
        let pub_key = pub_key.public_key().to_string();

        let mut conn = self.write_pool.get()?;
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            {
                let query = if positive {
                    "UPDATE account SET balance=balance + ?1 WHERE pubkey=?2"
                } else {
                    "UPDATE account SET balance=balance - ?1 WHERE pubkey=?2"
                };
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![new_balance, pub_key])?;
            }
            tx.commit()?;
            let ok: Result<()> = Ok(());
            ok
        })
        .await?
    }

    /// Create invoice record
    async fn create_invoice_record(&self, pub_key: &Keys, invoice_info: InvoiceInfo) -> Result<()> {
        let pub_key = pub_key.public_key().to_string();
        let pub_key = pub_key.to_owned();
        let mut conn = self.write_pool.get()?;
        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            {
                let query = "INSERT INTO invoice (pubkey, payment_hash, amount, status, description, created_at, invoice) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%s','now'), ?6);";
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![&pub_key, invoice_info.payment_hash, invoice_info.amount, invoice_info.status.to_string(), invoice_info.memo, invoice_info.bolt11])?;
            }
            tx.commit()?;
            let ok: Result<()> = Ok(());
            ok
        }).await??;

        Ok(())
    }

    /// Update invoice record
    async fn update_invoice(&self, payment_hash: &str, status: InvoiceStatus) -> Result<String> {
        let mut conn = self.write_pool.get()?;
        let payment_hash = payment_hash.to_owned();

        tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;
            let pubkey: String;
            {

                // Get required invoice info for given payment hash
                let query = "SELECT pubkey, status, amount FROM invoice WHERE payment_hash=?1;";
                let mut stmt = tx.prepare(query)?;
                let (pub_key, prev_status, amount) = stmt.query_row(params![payment_hash], |r| {
                    let pub_key: String = r.get(0)?;
                    let status: String = r.get(1)?;
                    let amount: u64 = r.get(2)?;


                    Ok((pub_key, status, amount))

                })?;

                // If the invoice is paid update the confirmed_at timestamp
                let query =  if status.eq(&InvoiceStatus::Paid) {
                    "UPDATE invoice SET status=?1, confirmed_at = strftime('%s', 'now') WHERE payment_hash=?2;"
                } else {
                    "UPDATE invoice SET status=?1 WHERE payment_hash=?2;"
                };
                let mut stmt = tx.prepare(query)?;
                stmt.execute(params![status.to_string(), payment_hash])?;

                // Increase account balance by given invoice amount
                if prev_status == "Unpaid" && status.eq(&InvoiceStatus::Paid) {
                    let query =
                            "UPDATE account SET balance = balance + ?1 WHERE pubkey = ?2;";
                    let mut stmt = tx.prepare(query)?;
                    stmt.execute(params![amount, pub_key])?;
                }

                pubkey = pub_key;
            }

            tx.commit()?;
            let ok: Result<String> = Ok(pubkey);
            ok
        })
        .await?
    }

    /// Get the most recent invoice for a given pubkey
    /// invoice must be unpaid and not expired
    async fn get_unpaid_invoice(&self, pubkey: &Keys) -> Result<Option<InvoiceInfo>> {
        let mut conn = self.write_pool.get()?;

        let pubkey = pubkey.to_owned();
        let pubkey_str = pubkey.clone().public_key().to_string();
        let (payment_hash, invoice, amount, description) = tokio::task::spawn_blocking(move || {
            let tx = conn.transaction()?;

            let query = r#"
SELECT amount, payment_hash, description, invoice
FROM invoice
WHERE pubkey = ?1 AND status = 'Unpaid'
ORDER BY created_at DESC
LIMIT 1;
        "#;
            let mut stmt = tx.prepare(query).unwrap();
            stmt.query_row(params![&pubkey_str], |r| {
                let amount: u64 = r.get(0)?;
                let payment_hash: String = r.get(1)?;
                let description: String = r.get(2)?;
                let invoice: String = r.get(3)?;

                Ok((payment_hash, invoice, amount, description))
            })
        })
        .await??;

        Ok(Some(InvoiceInfo {
            pubkey: pubkey.public_key().to_string(),
            payment_hash,
            bolt11: invoice,
            amount,
            status: InvoiceStatus::Unpaid,
            memo: description,
            confirmed_at: None,
        }))
    }

    /// Query gift wrap events for a specific pubkey
    async fn query_gift_wraps_for_pubkey(
        &self,
        pubkey: &str,
        limit: Option<u64>,
        since: Option<u64>,
        until: Option<u64>,
    ) -> Result<Vec<Event>> {
        let start = Instant::now();
        let pool = self.read_pool.clone();
        let permit = self.reader_threads_ready.acquire().await.unwrap();
        
        let task = task::spawn_blocking(move || {
            let mut events = Vec::new();
            let conn = pool.get()?;
            
            // Prepare the SQL query
            let mut sql = String::from(
                "SELECT e.id, e.pubkey, e.created_at, e.kind, e.content, e.sig, e.tags 
                FROM event e
                JOIN gift_wrap_idx g ON e.id = g.event_id
                WHERE g.pubkey = ?1"
            );
            
            // Add optional conditions
            if let Some(since_time) = since {
                sql.push_str(" AND e.created_at >= ?2");
            }
            if let Some(until_time) = until {
                sql.push_str(" AND e.created_at <= ?3");
            }
            
            // Add order and limit
            sql.push_str(" ORDER BY e.created_at DESC");
            if let Some(limit_count) = limit {
                sql.push_str(" LIMIT ?4");
            }
            
            // Prepare the statement
            let mut stmt = conn.prepare(&sql)?;
            
            // Execute with appropriate parameters
            let rows = match (since, until, limit) {
                (Some(since_time), Some(until_time), Some(limit_count)) => {
                    stmt.query(params![pubkey, since_time, until_time, limit_count])?
                }
                (Some(since_time), Some(until_time), None) => {
                    stmt.query(params![pubkey, since_time, until_time])?
                }
                (Some(since_time), None, Some(limit_count)) => {
                    stmt.query(params![pubkey, since_time, limit_count])?
                }
                (Some(since_time), None, None) => {
                    stmt.query(params![pubkey, since_time])?
                }
                (None, Some(until_time), Some(limit_count)) => {
                    stmt.query(params![pubkey, until_time, limit_count])?
                }
                (None, Some(until_time), None) => {
                    stmt.query(params![pubkey, until_time])?
                }
                (None, None, Some(limit_count)) => {
                    stmt.query(params![pubkey, limit_count])?
                }
                (None, None, None) => {
                    stmt.query(params![pubkey])?
                }
            };
            
            // Process the results
            let mut rows = rows;
            while let Some(row) = rows.next()? {
                let mut event = Event {
                    id: row.get(0)?,
                    pubkey: row.get(1)?,
                    delegated_by: None,
                    created_at: row.get(2)?,
                    kind: row.get(3)?,
                    content: row.get(4)?,
                    sig: row.get(5)?,
                    tags: serde_json::from_str(row.get::<_, String>(6)?.as_str())?,
                    tagidx: None,
                };
                event.build_index();
                event.update_delegation();
                events.push(event);
            }
            
            Ok(events)
        });
        
        drop(permit);
        let events = task.await.unwrap()?;
        
        let duration = start.elapsed();
        self.metrics.query_db.observe(duration.as_secs_f64());
        
        Ok(events)
    }

    /// Query encrypted direct messages for a specific pubkey
    async fn query_encrypted_dms_for_pubkey(
        &self,
        pubkey: &str,
        limit: Option<u64>,
        since: Option<u64>,
        until: Option<u64>,
    ) -> Result<Vec<Event>> {
        let start = Instant::now();
        let pool = self.read_pool.clone();
        let permit = self.reader_threads_ready.acquire().await.unwrap();
        
        let task = task::spawn_blocking(move || {
            let mut events = Vec::new();
            let conn = pool.get()?;
            
            // Prepare the SQL query
            let mut sql = String::from(
                "SELECT e.id, e.pubkey, e.created_at, e.kind, e.content, e.sig, e.tags 
                FROM event e
                WHERE (e.kind IN (4, 44) AND e.id IN (
                    SELECT event_id FROM tag 
                    WHERE name='p' AND value=?1
                ))
                OR (e.kind IN (4, 44) AND e.pubkey=?1)"
            );
            
            // Add optional conditions
            if let Some(since_time) = since {
                sql.push_str(" AND e.created_at >= ?2");
            }
            if let Some(until_time) = until {
                sql.push_str(" AND e.created_at <= ?3");
            }
            
            // Add order and limit
            sql.push_str(" ORDER BY e.created_at DESC");
            if let Some(limit_count) = limit {
                sql.push_str(" LIMIT ?4");
            }
            
            // Prepare the statement
            let mut stmt = conn.prepare(&sql)?;
            
            // Execute with appropriate parameters based on optional args
            let rows = match (since, until, limit) {
                (Some(since_time), Some(until_time), Some(limit_count)) => {
                    stmt.query(params![pubkey, since_time, until_time, limit_count])?
                }
                (Some(since_time), Some(until_time), None) => {
                    stmt.query(params![pubkey, since_time, until_time])?
                }
                (Some(since_time), None, Some(limit_count)) => {
                    stmt.query(params![pubkey, since_time, limit_count])?
                }
                (Some(since_time), None, None) => {
                    stmt.query(params![pubkey, since_time])?
                }
                (None, Some(until_time), Some(limit_count)) => {
                    stmt.query(params![pubkey, until_time, limit_count])?
                }
                (None, Some(until_time), None) => {
                    stmt.query(params![pubkey, until_time])?
                }
                (None, None, Some(limit_count)) => {
                    stmt.query(params![pubkey, limit_count])?
                }
                (None, None, None) => {
                    stmt.query(params![pubkey])?
                }
            };
            
            // Process the results
            let mut rows = rows;
            while let Some(row) = rows.next()? {
                let mut event = Event {
                    id: row.get(0)?,
                    pubkey: row.get(1)?,
                    delegated_by: None,
                    created_at: row.get(2)?,
                    kind: row.get(3)?,
                    content: row.get(4)?,
                    sig: row.get(5)?,
                    tags: serde_json::from_str(row.get::<_, String>(6)?.as_str())?,
                    tagidx: None,
                };
                event.build_index();
                event.update_delegation();
                events.push(event);
            }
            
            Ok(events)
        });
        
        drop(permit);
        let events = task.await.unwrap()?;
        
        let duration = start.elapsed();
        self.metrics.query_db.observe(duration.as_secs_f64());
        
        Ok(events)
    }

    /// Query NIP-17 private direct messages for a specific pubkey
    async fn query_private_dms_for_pubkey(
        &self,
        pubkey: &str,
        limit: Option<u64>,
        since: Option<u64>,
        until: Option<u64>,
    ) -> Result<Vec<Event>> {
        let start = Instant::now();
        let pool = self.read_pool.clone();
        let permit = self.reader_threads_ready.acquire().await.unwrap();
        
        let task = task::spawn_blocking(move || {
            let mut events = Vec::new();
            let conn = pool.get()?;
            
            // Prepare the SQL query to find direct messages where:
            // 1. The pubkey is directly in a p-tag
            // 2. OR The pubkey is the author
            let mut sql = String::from(
                "SELECT DISTINCT e.id, e.pubkey, e.created_at, e.kind, e.content, e.sig, e.tags 
                FROM event e
                WHERE (e.kind IN (14, 15) AND e.id IN (
                    SELECT event_id FROM gift_wrap_idx 
                    WHERE pubkey=?1
                ))
                OR (e.kind IN (14, 15) AND e.pubkey=?1)"
            );
            
            // Add optional conditions
            if let Some(since_time) = since {
                sql.push_str(" AND e.created_at >= ?2");
            }
            if let Some(until_time) = until {
                sql.push_str(" AND e.created_at <= ?3");
            }
            
            // Add order and limit
            sql.push_str(" ORDER BY e.created_at DESC");
            if let Some(limit_count) = limit {
                sql.push_str(" LIMIT ?4");
            }
            
            // Prepare and execute the query with appropriate parameters
            let mut stmt = conn.prepare(&sql)?;
            let rows = match (since, until, limit) {
                (Some(since_time), Some(until_time), Some(limit_count)) => {
                    stmt.query(params![pubkey, since_time, until_time, limit_count])?
                }
                (Some(since_time), Some(until_time), None) => {
                    stmt.query(params![pubkey, since_time, until_time])?
                }
                (Some(since_time), None, Some(limit_count)) => {
                    stmt.query(params![pubkey, since_time, limit_count])?
                }
                (Some(since_time), None, None) => {
                    stmt.query(params![pubkey, since_time])?
                }
                (None, Some(until_time), Some(limit_count)) => {
                    stmt.query(params![pubkey, until_time, limit_count])?
                }
                (None, Some(until_time), None) => {
                    stmt.query(params![pubkey, until_time])?
                }
                (None, None, Some(limit_count)) => {
                    stmt.query(params![pubkey, limit_count])?
                }
                (None, None, None) => {
                    stmt.query(params![pubkey])?
                }
            };
            
            // Process the results
            let mut rows = rows;
            while let Some(row) = rows.next()? {
                let mut event = Event {
                    id: row.get(0)?,
                    pubkey: row.get(1)?,
                    delegated_by: None,
                    created_at: row.get(2)?,
                    kind: row.get(3)?,
                    content: row.get(4)?,
                    sig: row.get(5)?,
                    tags: serde_json::from_str(row.get::<_, String>(6)?.as_str())?,
                    tagidx: None,
                };
                event.build_index();
                event.update_delegation();
                events.push(event);
            }
            
            Ok(events)
        });
        
        drop(permit);
        let events = task.await.unwrap()?;
        
        let duration = start.elapsed();
        self.metrics.query_db.observe(duration.as_secs_f64());
        
        Ok(events)
    }
}

/// Decide if there is an index that should be used explicitly
fn override_index(f: &ReqFilter) -> Option<String> {
    if f.ids.is_some() {
        return Some("event_hash_index".into());
    }
    // queries for multiple kinds default to kind_index, which is
    // significantly slower than kind_created_at_index.
    if let Some(ks) = &f.kinds {
        if f.ids.is_none()
            && ks.len() > 1
            && f.since.is_none()
            && f.until.is_none()
            && f.tags.is_none()
            && f.authors.is_none()
        {
            return Some("kind_created_at_index".into());
        }
    }
    // if there is an author, it is much better to force the authors index.
    if f.authors.is_some() {
        if f.since.is_none() && f.until.is_none() && f.limit.is_none() {
            if f.kinds.is_none() {
                // with no use of kinds/created_at, just author
                return Some("author_index".into());
            }
            // prefer author_kind if there are kinds
            return Some("author_kind_index".into());
        }
        // finally, prefer author_created_at if time is provided
        return Some("author_created_at_index".into());
    }
    None
}

/// Create a dynamic SQL subquery and params from a subscription filter (and optional explicit index used)
fn query_from_filter(f: &ReqFilter) -> (String, Vec<Box<dyn ToSql>>, Option<String>) {
    // build a dynamic SQL query.  all user-input is either an integer
    // (sqli-safe), or a string that is filtered to only contain
    // hexadecimal characters.  Strings that require escaping (tag
    // names/values) use parameters.

    // if the filter is malformed, don't return anything.
    if f.force_no_match {
        let empty_query = "SELECT e.content FROM event e WHERE 1=0".to_owned();
        // query parameters for SQLite
        let empty_params: Vec<Box<dyn ToSql>> = vec![];
        return (empty_query, empty_params, None);
    }

    // check if the index needs to be overridden
    let idx_name = override_index(f);
    let idx_stmt = idx_name
        .as_ref()
        .map_or_else(|| "".to_owned(), |i| format!("INDEXED BY {i}"));
    let mut query = format!("SELECT e.content FROM event e {idx_stmt}");
    // query parameters for SQLite
    let mut params: Vec<Box<dyn ToSql>> = vec![];

    // individual filter components (single conditions such as an author or event ID)
    let mut filter_components: Vec<String> = Vec::new();
    // Query for "authors", allowing prefix matches
    if let Some(authvec) = &f.authors {
        // take each author and convert to a hexsearch
        let mut auth_searches: Vec<String> = vec![];
        for auth in authvec {
            auth_searches.push("author=?".to_owned());
            let auth_bin = hex::decode(auth).ok();
            params.push(Box::new(auth_bin));
        }
        if !authvec.is_empty() {
            let auth_clause = format!("({})", auth_searches.join(" OR "));
            filter_components.push(auth_clause);
        } else {
            filter_components.push("false".to_owned());
        }
    }
    // Query for Kind
    if let Some(ks) = &f.kinds {
        // kind is number, no escaping needed
        let str_kinds: Vec<String> = ks.iter().map(std::string::ToString::to_string).collect();
        let kind_clause = format!("kind IN ({})", str_kinds.join(", "));
        filter_components.push(kind_clause);
    }
    // Query for event, allowing prefix matches
    if let Some(idvec) = &f.ids {
        // take each author and convert to a hexsearch
        let mut id_searches: Vec<String> = vec![];
        for id in idvec {
            id_searches.push("event_hash=?".to_owned());
            let id_bin = hex::decode(id).ok();
            params.push(Box::new(id_bin));
        }
        if idvec.is_empty() {
            // if the ids list was empty, we should never return
            // any results.
            filter_components.push("false".to_owned());
        } else {
            let id_clause = format!("({})", id_searches.join(" OR "));
            filter_components.push(id_clause);
        }
    }
    // Query for tags
    if let Some(map) = &f.tags {
        for (key, val) in map.iter() {
            let mut str_vals: Vec<Box<dyn ToSql>> = vec![];
            for v in val {
                str_vals.push(Box::new(v.clone()));
            }
            // create clauses with "?" params for each tag value being searched
            let str_clause = format!("AND value IN ({})", repeat_vars(str_vals.len()));
            // find evidence of the target tag name/value existing for this event.
            // Query for Kind/Since/Until additionally, to reduce the number of tags that come back.
            let kind_clause;
            if let Some(ks) = &f.kinds {
                // kind is number, no escaping needed
                let str_kinds: Vec<String> =
                    ks.iter().map(std::string::ToString::to_string).collect();
                kind_clause = format!("AND kind IN ({})", str_kinds.join(", "));
            } else {
                kind_clause = String::new();
            };
            let since_clause = if f.since.is_some() {
                format!("AND created_at >= {}", f.since.unwrap())
            } else {
                String::new()
            };
            // Query for timestamp
            let until_clause = if f.until.is_some() {
                format!("AND created_at <= {}", f.until.unwrap())
            } else {
                String::new()
            };

            let tag_clause = format!(
		"e.id IN (SELECT t.event_id FROM tag t WHERE (name=? {str_clause} {kind_clause} {since_clause} {until_clause}))"
            );

            // add the tag name as the first parameter
            params.push(Box::new(key.to_string()));
            // add all tag values that are blobs as params
            params.append(&mut str_vals);
            filter_components.push(tag_clause);
        }
    }
    // Query for timestamp
    if f.since.is_some() {
        let created_clause = format!("created_at >= {}", f.since.unwrap());
        filter_components.push(created_clause);
    }
    // Query for timestamp
    if f.until.is_some() {
        let until_clause = format!("created_at <= {}", f.until.unwrap());
        filter_components.push(until_clause);
    }
    // never display hidden events
    query.push_str(" WHERE hidden!=TRUE");
    // never display hidden events
    filter_components.push("(expires_at IS NULL OR expires_at > ?)".to_string());
    params.push(Box::new(unix_time()));
    // build filter component conditions
    if !filter_components.is_empty() {
        query.push_str(" AND ");
        query.push_str(&filter_components.join(" AND "));
    }
    // Apply per-filter limit to this subquery.
    // The use of a LIMIT implies a DESC order, to capture only the most recent events.
    if let Some(lim) = f.limit {
        let _ = write!(query, " ORDER BY e.created_at DESC LIMIT {lim}");
    } else {
        query.push_str(" ORDER BY e.created_at ASC");
    }

    // Special handling for gift wraps (kind 1059)
    if let Some(kinds) = &f.kinds {
        if kinds.contains(&1059) && f.authors.is_some() {
            // If we have gift wrap kind and author filters, also include the gift wrap index
            if !query.contains("gift_wrap_idx") {
                query.push_str(" LEFT JOIN gift_wrap_idx g ON e.id = g.event_id");
                
                // Add a condition for gift wrap recipients in the WHERE clause
                if let Some(authors) = &f.authors {
                    if !authors.is_empty() {
                        if !filter_components.is_empty() {
                            query.push_str(" AND ");
                        }
                        
                        if authors.len() == 1 {
                            query.push_str("(g.pubkey = ?");
                            params.push(Box::new(authors[0].clone()));
                        } else {
                            query.push_str("(g.pubkey IN (");
                            for (i, author) in authors.iter().enumerate() {
                                if i > 0 {
                                    query.push_str(",?");
                                } else {
                                    query.push('?');
                                }
                                params.push(Box::new(author.clone()));
                            }
                            query.push(')');
                        }
                        query.push_str(" OR e.kind != 1059)");
                    }
                }
            }
        }
    }

    (query, params, idx_name)
}

/// Create a dynamic SQL query string and params from a subscription.
fn _query_from_sub(sub: &Subscription) -> (String, Vec<Box<dyn ToSql>>, Vec<String>) {
    // build a dynamic SQL query for an entire subscription, based on
    // SQL subqueries for filters.
    let mut subqueries: Vec<String> = Vec::new();
    let mut indexes = vec![];
    // subquery params
    let mut params: Vec<Box<dyn ToSql>> = vec![];
    // for every filter in the subscription, generate a subquery
    for f in &sub.filters {
        let (f_subquery, mut f_params, index) = query_from_filter(f);
        if let Some(i) = index {
            indexes.push(i);
        }
        subqueries.push(f_subquery);
        params.append(&mut f_params);
    }
    // encapsulate subqueries into select statements
    let subqueries_selects: Vec<String> = subqueries
        .iter()
        .map(|s| format!("SELECT distinct content, created_at FROM ({s})"))
        .collect();
    let query: String = subqueries_selects.join(" UNION ");
    (query, params, indexes)
}

/// Build a database connection pool.
/// # Panics
///
/// Will panic if the pool could not be created.
#[must_use]
pub fn build_pool(
    name: &str,
    settings: &Settings,
    flags: OpenFlags,
    min_size: u32,
    max_size: u32,
    wait_for_db: bool,
) -> SqlitePool {
    let db_dir = &settings.database.data_directory;
    let full_path = Path::new(db_dir).join(DB_FILE);

    // small hack; if the database doesn't exist yet, that means the
    // writer thread hasn't finished.  Give it a chance to work.  This
    // is only an issue with the first time we run.
    if !settings.database.in_memory {
        while !full_path.exists() && wait_for_db {
            debug!("Database reader pool is waiting on the database to be created...");
            thread::sleep(Duration::from_millis(500));
        }
    }
    let manager = if settings.database.in_memory {
        SqliteConnectionManager::file("file::memory:?cache=shared")
            .with_flags(flags)
            .with_init(|c| c.execute_batch(STARTUP_SQL))
    } else {
        SqliteConnectionManager::file(&full_path)
            .with_flags(flags)
            .with_init(|c| c.execute_batch(STARTUP_SQL))
    };
    let pool: SqlitePool = r2d2::Pool::builder()
        .test_on_check_out(true) // no noticeable performance hit
        .min_idle(Some(min_size))
        .max_size(max_size)
        .idle_timeout(Some(Duration::from_secs(10)))
        .max_lifetime(Some(Duration::from_secs(30)))
        .build(manager)
        .unwrap();
    // retrieve a connection to ensure the startup statements run immediately
    {
        let _ = pool.get();
    }

    info!(
        "Built a connection pool {:?} (min={}, max={})",
        name, min_size, max_size
    );
    pool
}

/// Cleanup expired events on a regular basis
async fn cleanup_expired(
    pool: SqlitePool,
    frequency: Duration,
    write_in_progress: Arc<Mutex<u64>>,
) -> Result<()> {
    tokio::task::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(frequency) => {
                    if let Ok(mut conn) = pool.get() {
                        let mut _guard:Option<MutexGuard<u64>> = None;
                        // take a write lock to prevent event writes
                        // from proceeding while we are deleting
                        // events.  This isn't necessary, but
                        // minimizes the chances of forcing event
                        // persistence to be retried.
                        _guard = Some(write_in_progress.lock().await);
                        let start = Instant::now();
                        let exp_res = tokio::task::spawn_blocking(move || {
                            delete_expired(&mut conn)
                        }).await;
                        match exp_res {
                            Ok(Ok(count)) => {
                                if count > 0 {
                                    info!("removed {} expired events in: {:?}", count, start.elapsed());
                                }
                            },
                            _ => {
                                // either the task or underlying query failed
                                info!("there was an error cleaning up expired events: {:?}", exp_res);
                            }
                        }
                    }
                }
            };
        }
    });
    Ok(())
}

/// Execute a query to delete all expired events
pub fn delete_expired(conn: &mut PooledConnection) -> Result<usize> {
    let tx = conn.transaction()?;
    let update_count = tx.execute(
        "DELETE FROM event WHERE expires_at <= ?",
        params![unix_time()],
    )?;
    tx.commit()?;
    Ok(update_count)
}

/// Perform database WAL checkpoint on a regular basis
pub async fn db_checkpoint_task(
    pool: SqlitePool,
    frequency: Duration,
    write_in_progress: Arc<Mutex<u64>>,
    checkpoint_in_progress: Arc<Mutex<u64>>,
) -> Result<()> {
    // TODO; use acquire_many on the reader semaphore to stop them from interrupting this.
    tokio::task::spawn(async move {
        // WAL size in pages.
        let mut current_wal_size = 0;
        // WAL threshold for more aggressive checkpointing (10,000 pages, or about 40MB)
        let wal_threshold = 1000 * 10;
        // default threshold for the busy timer
        let busy_wait_default = Duration::from_secs(1);
        // if the WAL file is getting too big, switch to this
        let busy_wait_default_long = Duration::from_secs(10);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(frequency) => {
                    if let Ok(mut conn) = pool.get() {
                        // block all other writers
                        let _write_guard = write_in_progress.lock().await;
                        let mut _guard:Option<MutexGuard<u64>> = None;
                        // the busy timer will block writers, so don't set
                        // this any higher than you want max latency for event
                        // writes.
                        if current_wal_size <= wal_threshold {
                            conn.busy_timeout(busy_wait_default).ok();
                        } else {
                            // if the wal size has exceeded a threshold, increase the busy timeout.
                            conn.busy_timeout(busy_wait_default_long).ok();
                            // take a lock that will prevent new readers.
                            info!("blocking new readers to perform wal_checkpoint");
                            _guard = Some(checkpoint_in_progress.lock().await);
                        }
                        debug!("running wal_checkpoint(TRUNCATE)");
                        if let Ok(new_size) = checkpoint_db(&mut conn) {
                            current_wal_size = new_size;
                        }
                    }
                }
            };
        }
    });

    Ok(())
}

#[derive(Debug)]
#[allow(dead_code)]
enum SqliteStatus {
    Ok,
    Busy,
    Error,
    Other(u64),
}

/// Checkpoint/Truncate WAL.  Returns the number of WAL pages remaining.
pub fn checkpoint_db(conn: &mut PooledConnection) -> Result<usize> {
    let query = "PRAGMA wal_checkpoint(TRUNCATE);";
    let start = Instant::now();
    let (cp_result, wal_size, _frames_checkpointed) = conn.query_row(query, [], |row| {
        let checkpoint_result: u64 = row.get(0)?;
        let wal_size: u64 = row.get(1)?;
        let frames_checkpointed: u64 = row.get(2)?;
        Ok((checkpoint_result, wal_size, frames_checkpointed))
    })?;
    let result = match cp_result {
        0 => SqliteStatus::Ok,
        1 => SqliteStatus::Busy,
        2 => SqliteStatus::Error,
        x => SqliteStatus::Other(x),
    };
    info!(
        "checkpoint ran in {:?} (result: {:?}, WAL size: {})",
        start.elapsed(),
        result,
        wal_size
    );
    Ok(wal_size as usize)
}

/// Produce a arbitrary list of '?' parameters.
fn repeat_vars(count: usize) -> String {
    if count == 0 {
        return "".to_owned();
    }
    let mut s = "?,".repeat(count);
    // Remove trailing comma
    s.pop();
    s
}

/// Display database pool stats every 1 minute
pub async fn monitor_pool(name: &str, pool: SqlitePool) {
    let sleep_dur = Duration::from_secs(60);
    loop {
        log_pool_stats(name, &pool);
        tokio::time::sleep(sleep_dur).await;
    }
}

/// Log pool stats
fn log_pool_stats(name: &str, pool: &SqlitePool) {
    let state: r2d2::State = pool.state();
    let in_use_cxns = state.connections - state.idle_connections;
    debug!(
        "DB pool {:?} usage (in_use: {}, available: {}, max: {})",
        name,
        in_use_cxns,
        state.connections,
        pool.max_size()
    );
}

/// Check if the pool is fully utilized
fn _pool_at_capacity(pool: &SqlitePool) -> bool {
    let state: r2d2::State = pool.state();
    state.idle_connections == 0
}

// Add this function to create gift wrap tables
fn create_gift_wrap_tables(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS gift_wrap_idx (
            event_id TEXT NOT NULL,
            pubkey TEXT NOT NULL,
            PRIMARY KEY (event_id, pubkey)
        )",
        [],
    )?;
    
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_gift_wrap_pubkey ON gift_wrap_idx (pubkey)",
        [],
    )?;
    
    Ok(())
}

// Modify the init_db_tables function to call create_gift_wrap_tables
fn init_db_tables(conn: &rusqlite::Connection) -> Result<()> {
    // Create tables for NIP-17 support
    create_gift_wrap_tables(conn)?;
    
    // ... rest of existing code ...
}
