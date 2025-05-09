# Docker Build Fix for Nostr-rs-relay

## Problem

The Docker build for nostr-rs-relay fails due to a dependency conflict between two packages that both link to SQLite:

1. `rusqlite` requires `libsqlite3-sys` version `^0.25.0`
2. `sqlx` requires `libsqlite3-sys` version `^0.24.1`

Since they both link to the same native library (`sqlite3`), Cargo doesn't allow two different versions in the same build.

## Solution

We've created an alternative Dockerfile (`Dockerfile.sqlite`) that builds a known working version of the relay (0.8.9). This version predates some of the dependency conflicts while still providing the core relay functionality.

### How to use it:

1. Build the Docker image:

```bash
docker build -f Dockerfile.sqlite -t nostr-rs-relay:latest .
```

2. Create a directory for the database:

```bash
mkdir -p db
```

3. Run the container:

```bash
docker run -p 8080:8080 -v $(pwd)/db:/usr/src/app/db nostr-rs-relay:latest
```

## Alternative Solutions

If you need to use the current version with all features, consider these options:

1. **Fork the repository and fix the dependencies**:

   - Update `sqlx` to use the same version of `libsqlite3-sys` as `rusqlite`
   - Or pin `rusqlite` to use the same version of `libsqlite3-sys` as `sqlx`

2. **Report the issue to the project maintainers**:
   - Create a detailed issue report with the error messages
   - Request a fix for the dependency conflict

## Implemented Features

The current codebase includes implementations for:

- NIP-44 (Encrypted Payloads)
- NIP-59 (Gift Wrap)
- NIP-17 (Private Direct Messages)

These implementations are in the source code, but the Docker build issues prevent them from being used in a container. If you need these features, you may need to build the application directly on your machine or use one of the alternative solutions mentioned above.
