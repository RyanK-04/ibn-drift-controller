#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Stopping Docker Compose services..."
docker compose down --remove-orphans

echo "Destroying Containerlab nodes while preserving ibn_net..."
sudo clab destroy -t topology.yml --keep-mgmt-net

echo "Lab stopped. The ibn_net management network is preserved."