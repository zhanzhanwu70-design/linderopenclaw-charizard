#!/bin/bash
# network-anomaly-detector.sh

# Monitor OpenClaw network connections
while true; do
  # Check for unusual network connections on port 18789 (OpenClaw gateway)
  OPENCLAW_CONNECTIONS=$(lsof -i :18789 2>/dev/null | grep -v "PID")
  EXPECTED_CONNECTIONS=1
  
  if [ -n "$OPENCLAW_CONNECTIONS" ]; then
    CONNECTION_COUNT=$(echo "$OPENCLAW_CONNECTIONS" | wc -l)
    if [ "$CONNECTION_COUNT" -gt "$EXPECTED_CONNECTIONS" ]; then
      echo "$(date): UNUSUAL NETWORK ACTIVITY - $CONNECTION_COUNT connections on port 18789" >> $HOME/openclaw-network-anomaly.log
      echo "$OPENCLAW_CONNECTIONS" >> $HOME/openclaw-network-anomaly.log
    fi
  fi
  
  # Check for connections to unexpected ports
  UNEXPECTED_PORTS=$(lsof -i -P | grep "openclaw" | grep -v ":18789")
  if [ -n "$UNEXPECTED_PORTS" ]; then
    echo "$(date): OPENCLAW CONNECTING TO UNEXPECTED PORTS:" >> $HOME/openclaw-network-anomaly.log
    echo "$UNEXPECTED_PORTS" >> $HOME/openclaw-network-anomaly.log
  fi
  
  sleep 30
done
