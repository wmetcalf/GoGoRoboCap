#!/bin/bash

# Build script for GoGoRoboCap - builds for Linux, macOS, and Windows x86_64

echo "Building GoGoRoboCap for multiple platforms..."

# Create builds directory
mkdir -p builds

# Build for Linux x86_64
echo "Building for Linux x86_64..."
GOOS=linux GOARCH=amd64 go build -o builds/gogorobocap-linux-amd64 .

# Build for macOS x86_64
echo "Building for macOS x86_64..."
GOOS=darwin GOARCH=amd64 go build -o builds/gogorobocap-darwin-amd64 .

# Build for macOS ARM64 (Apple Silicon)
echo "Building for macOS ARM64 (Apple Silicon)..."
GOOS=darwin GOARCH=arm64 go build -o builds/gogorobocap-darwin-arm64 .

# Build for Windows x86_64
echo "Building for Windows x86_64..."
GOOS=windows GOARCH=amd64 go build -o builds/gogorobocap-windows-amd64.exe .

echo "Build complete! Binaries are in the builds/ directory:"
ls -la builds/
