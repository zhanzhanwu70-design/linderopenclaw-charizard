#!/bin/bash
# process-anomaly-detector.sh

# Monitor for suspicious OpenClaw processes
while true; do
  # Check for OpenClaw processes with unusual arguments
  SUSPICIOUS_PROCESSES=$(ps aux | grep -E "(openclaw|clawdbot)" | grep -E "(sh|bash|python|perl|nc|netcat|curl|wget)" | grep -v grep)
  
  if [ -n "$SUSPICIOUS_PROCESSES" ]; then
    echo "$(date): SUSPICIOUS OPENCLAW PROCESSES DETECTED:" >> $HOME/openclaw-process-anomaly.log
    echo "$SUSPICIOUS_PROCESSES" >> $HOME/openclaw-process-anomaly.log
  fi
  
  # Check for processes trying to inject into OpenClaw
  INJECTION_ATTEMPTS=$(ps aux | grep -E "(gdb|lldb|strace|dtruss)" | grep -E "(openclaw|clawdbot)" | grep -v grep)
  
  if [ -n "$INJECTION_ATTEMPTS" ]; then
    echo "$(date): PROCESS INJECTION ATTEMPT DETECTED:" >> $HOME/openclaw-process-anomaly.log
    echo "$INJECTION_ATTEMPTS" >> $HOME/openclaw-process-anomaly.log
  fi
  
  sleep 15
done
