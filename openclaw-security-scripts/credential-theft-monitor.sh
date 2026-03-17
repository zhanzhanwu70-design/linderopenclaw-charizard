#!/bin/bash
# credential-theft-monitor.sh

# Monitor processes trying to access OpenClaw credentials
while true; do
  # Check for suspicious processes reading credential files
  ps aux | grep -E "(cat|less|more|vim|nano|emacs)" | grep -v grep | while read line; do
    if echo "$line" | grep -q "openclaw\|\.env"; then
      PID=$(echo "$line" | awk '{print $2}')
      CMD=$(echo "$line" | awk '{print $11}')
      USER=$(echo "$line" | awk '{print $1}')
      
      echo "$(date): SUSPICIOUS CREDENTIAL ACCESS - PID: $PID, CMD: $CMD, USER: $USER" >> $HOME/openclaw-credential-theft.log
    fi
  done
  
  sleep 10
done
