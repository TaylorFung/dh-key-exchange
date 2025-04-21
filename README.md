# Diffie-Hellman Key Exchange Implementation in C++

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A secure implementation of the Diffie-Hellman key exchange protocol using OpenSSL, featuring 256-bit safe prime generation and Base64-encoded output.

## Features

- 🔒 **256-bit secure prime number generation** with OpenSSL
- 🔑 Automatic private/public key pair generation
- 📊 Base64-encoded output for all parameters
- 🛡️ Secure cryptographic operations using:
  - `BN_*` functions for big number operations
  - `EVP_*` interfaces for hashing
- 📦 Modular code structure with separated headers/sources
- 🏗️ CMake build system support

## Prerequisites

- OpenSSL 1.1.1 or later
- CMake 3.10+
- C++17 compatible compiler (GCC 9+, Clang 10+)

## Build Instructions

```bash
# Clone the repository
git clone https://github.com/yourusername/dh-key-exchange.git
cd dh-key-exchange

# Install dependencies (Ubuntu/Debian)
sudo apt update && sudo apt install -y cmake libssl-dev g++

# Build the project
mkdir build && cd build
cmake .. && make