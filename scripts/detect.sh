#!/bin/bash

set -e

echo "=== Starting Automatic Project Type Detection ==="

# Fallback for GITHUB_OUTPUT to allow local testing
if [ -z "$GITHUB_OUTPUT" ]; then
    echo "[DEBUG] GITHUB_OUTPUT not set. Redirecting output to stdout."
    GITHUB_OUTPUT=/dev/stdout
fi

if [ -f pom.xml ]; then
    echo "[INFO] Found 'pom.xml'. Project Type: Java (Maven)."
    echo "language=java" >> "$GITHUB_OUTPUT"
    echo "languages=[\"java\"]" >> "$GITHUB_OUTPUT"

elif [ -f requirements.txt ] || [ -f pyproject.toml ]; then
    echo "[INFO] Found Python build files. Project Type: Python."
    echo "language=python" >> "$GITHUB_OUTPUT"
    echo "languages=[\"python\"]" >> "$GITHUB_OUTPUT"

elif [ -f go.mod ]; then
    echo "[INFO] Found 'go.mod'. Project Type: Go."
    echo "language=go" >> "$GITHUB_OUTPUT"
    echo "languages=[\"go\"]" >> "$GITHUB_OUTPUT"

elif [ -n "$(find . -maxdepth 2 \( -name "*.sln" -o -name "*.csproj" \) -print -quit)" ]; then
    echo "[INFO] Found .NET solution or project files. Project Type: .NET."
    echo "language=dotnet" >> "$GITHUB_OUTPUT"
    echo "languages=[\"dotnet\"]" >> "$GITHUB_OUTPUT"

else
    echo "[ERROR] No supported project files (pom.xml, requirements.txt, pyproject.toml, go.mod, *.sln, *.csproj) found."
    echo "Unsupported project type"
    exit 1
fi

echo "=== Project Detection Completed ==="