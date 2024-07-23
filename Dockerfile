# Use the official Rust image as the build environment
FROM rust:latest as builder

# Set the working directory
WORKDIR /usr/src/app

# Copy the Cargo.toml and Cargo.lock files to the working directory
COPY Cargo.toml Cargo.lock ./

# Create a dummy file to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build the dependencies
RUN cargo build --debug
RUN rm -f target/release/deps/app*

# Copy the source code and build the final binary
COPY . .
RUN cargo build --debug

# Use a minimal base image for the final image
FROM debian:buster-slim

# Install necessary libraries
RUN apt-get update && apt-get install -y libssl-dev

# Copy the binary from the build stage
COPY --from=builder /usr/src/app/target/release/app /usr/local/bin/app

# Set the command to run the application
CMD ["app"]
