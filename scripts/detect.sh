#!/bin/bash

set -e

# Fallback for GITHUB_OUTPUT to allow local testing
if [ -z "$GITHUB_OUTPUT" ]; then
    GITHUB_OUTPUT=/dev/stdout
fi

if [ -f pom.xml ]; then
    echo "language=java" >> "$GITHUB_OUTPUT"
    echo "languages=[\"java\"]" >> "$GITHUB_OUTPUT"

elif [ -f requirements.txt ] || [ -f pyproject.toml ]; then
    echo "language=python" >> "$GITHUB_OUTPUT"
    echo "languages=[\"python\"]" >> "$GITHUB_OUTPUT"

elif [ -f go.mod ]; then
    echo "language=go" >> "$GITHUB_OUTPUT"
    echo "languages=[\"go\"]" >> "$GITHUB_OUTPUT"

elif [ -n "$(find . -maxdepth 2 \( -name "*.sln" -o -name "*.csproj" \) -print -quit)" ]; then
    echo "language=dotnet" >> "$GITHUB_OUTPUT"
    echo "languages=[\"dotnet\"]" >> "$GITHUB_OUTPUT"

else
    echo "Unsupported project type"
    exit 1
fi