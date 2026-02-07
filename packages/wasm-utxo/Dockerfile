# Start from a Node.js base image
FROM node:20

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install wasm-pack
RUN cargo install wasm-pack --version 0.14.0

# Install clang and binaryen (provides wasm-opt)
RUN apt-get update && apt-get install -y clang binaryen

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./
RUN npm install

# Bundle app source
COPY . .

# Build the project
RUN npm run build
