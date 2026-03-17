#!/bin/bash
# file-integrity-monitor.sh

CLAWDBOT_DIR="$HOME/.openclaw"
INTEGRITY_LOG="$HOME/openclaw-integrity.log"
HASH_FILE="/tmp/openclaw-file-hashes"

# Calculate initial file hashes
echo "$(date): Initializing file integrity monitoring..." >> $INTEGRITY_LOG
find "$CLAWDBOT_DIR" -type f -exec sha256sum {} \; > "$HASH_FILE" 2>/dev/null

# Monitor for changes
while true; do
  sleep 30
  
  find "$CLAWDBOT_DIR" -type f -exec sha256sum {} \; > /tmp/current-hashes 2>/dev/null
  
  if ! diff -q "$HASH_FILE" /tmp/current-hashes > /dev/null; then
    echo "$(date): FILE INTEGRITY CHANGE DETECTED!" >> $INTEGRITY_LOG
    diff "$HASH_FILE" /tmp/current-hashes >> $INTEGRITY_LOG
    cp /tmp/current-hashes "$HASH_FILE"
  fi
done
