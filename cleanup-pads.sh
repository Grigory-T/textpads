#!/bin/bash
set -euo pipefail

PAD_DATA_DIR="${PAD_DATA_DIR:-/opt/pad/data}"

mkdir -p "$PAD_DATA_DIR"
find "$PAD_DATA_DIR" -maxdepth 1 -type f \( -name '*.txt' -o -name '*.meta.json' \) -delete
