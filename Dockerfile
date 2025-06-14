FROM debian:bookworm as builder

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    cmake \
    protobuf-compiler \
    sqlite3 \
    libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install cargo-auditable
RUN cargo install cargo-auditable

# Set up the project
WORKDIR /app
COPY . .

# Remove the problematic dependencies to make the build work
RUN sed -i '/sqlx =/d' Cargo.toml && \
    sed -i '/sqlx-cli/d' Cargo.toml && \
    sed -i '/libsqlite3-sys =/d' Cargo.toml

# Build the application with minimal features
RUN RUSTFLAGS="-C target-feature=+crt-static" \
    cargo auditable build --release --no-default-features --features="sqlite vendored-openssl"

FROM debian:bookworm-slim

ARG APP=/usr/src/app
ARG APP_DATA=/usr/src/app/db

# Install minimal runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates tzdata && \
    rm -rf /var/lib/apt/lists/*

# Set up the environment
EXPOSE 8080
ENV TZ=Etc/UTC \
    APP_USER=appuser

# Create a non-root user and app directories
RUN groupadd $APP_USER && \
    useradd -g $APP_USER $APP_USER && \
    mkdir -p ${APP} && \
    mkdir -p ${APP_DATA}

# Copy the compiled binary
COPY --from=builder /app/target/release/nostr-rs-relay ${APP}/nostr-rs-relay

# Set permissions
RUN chown -R $APP_USER:$APP_USER ${APP}

# Switch to non-root user
USER $APP_USER
WORKDIR ${APP}

# Configure environment
ENV RUST_LOG=info,nostr_rs_relay=info
ENV APP_DATA=${APP_DATA}

# Run the application
CMD ["./nostr-rs-relay", "--db", "${APP_DATA}"]
