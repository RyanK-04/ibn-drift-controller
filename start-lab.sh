#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Generating device configurations..."
python3 provisioning/generate_configs.py

echo "Deploying Containerlab topology..."
sudo clab deploy -t topology.yml

echo "Starting Docker Compose services..."
docker compose up -d --force-recreate

echo "Checking service status..."
docker compose ps