/**
 * Anomaly Detection Scanner
 * 檢測異常行為模式
 */

class AnomalyScanner {
  constructor() {
    // 歷史資料
    this.toolHistory = [];
    this.maxHistory = 100;

    // 正常行為基線
    this.baseline = {
      avgCallsPerMinute: 5,
      peakHourlyTools: ['read', 'write', 'exec'],
      normalHours: { start: 6, end: 23 },
      maxCallsPerMinute: 30,
      maxSameToolConsecutive: 10,
    };

    // 異常時間（深夜）
    this.suspiciousHours = { start: 0, end: 5 };
  }

  async scan({ tool, arguments: args, argsStr }) {
    const findings = [];
    let riskScore = 0;
    const now = new Date();
    const hour = now.getHours();
    const minute = now.getMinutes();

    // 更新歷史
    this.updateHistory({ tool, timestamp: now.getTime() });

    // 1. 時間異常檢測
    if (this.isSuspiciousHour(hour)) {
      findings.push({
        type: 'suspicious_time',
        reason: `深夜時段執行 (${hour}:00)`,
        risk: 30,
        matches: [`hour: ${hour}`]
      });
      riskScore += 30;
    }

    // 2. 頻率異常檢測
    const callsInLastMinute = this.getCallsInLastMinute();
    if (callsInLastMinute > this.baseline.maxCallsPerMinute) {
      findings.push({
        type: 'frequency_anomaly',
        reason: `短時間內大量呼叫 (${callsInLastMinute}/min)`,
        risk: 55,
        matches: [`${callsInLastMinute} calls in 1 minute`]
      });
      riskScore += 55;
    }

    // 3. 連續相同工具呼叫
    const consecutiveCount = this.getConsecutiveCount(tool);
    if (consecutiveCount > this.baseline.maxSameToolConsecutive) {
      findings.push({
        type: 'consecutive_anomaly',
        reason: `連續呼叫相同工具 "${tool}" (${consecutiveCount}次)`,
        risk: 45,
        matches: [`${consecutiveCount} consecutive ${tool}`]
      });
      riskScore += 45;
    }

    // 4. 工具多樣性異常
    const toolDiversity = this.getToolDiversity();
    if (toolDiversity < 2 && this.toolHistory.length > 10) {
      findings.push({
        type: 'low_diversity',
        reason: '工具多樣性過低',
        risk: 25,
        matches: [`diversity: ${toolDiversity}`]
      });
      riskScore += 25;
    }

    // 5. 新工具檢測
    if (this.isNewTool(tool)) {
      findings.push({
        type: 'new_tool',
        reason: `首次使用工具 "${tool}"`,
        risk: 20,
        matches: ['new tool detected']
      });
      riskScore += 20;
    }

    // 6. 參數長度異常
    if (argsStr.length > 10000) {
      findings.push({
        type: 'large_parameters',
        reason: `參數過長 (${argsStr.length} chars)`,
        risk: 35,
        matches: [`${argsStr.length} characters`]
      });
      riskScore += 35;
    }

    // 7. 突發模式檢測
    if (this.isBurstPattern()) {
      findings.push({
        type: 'burst_pattern',
        reason: '突發呼叫模式',
        risk: 40,
        matches: ['burst detected']
      });
      riskScore += 40;
    }

    // 8. 上下文異常（跨 session）
    // 這需要與其他 scanner 配合

    return { riskScore: Math.min(riskScore, 100), findings };
  }

  updateHistory(entry) {
    this.toolHistory.push(entry);
    if (this.toolHistory.length > this.maxHistory) {
      this.toolHistory.shift();
    }
  }

  isSuspiciousHour(hour) {
    return hour >= this.suspiciousHours.start && hour <= this.suspiciousHours.end;
  }

  getCallsInLastMinute() {
    const cutoff = Date.now() - 60000;
    return this.toolHistory.filter(h => h.timestamp > cutoff).length;
  }

  getConsecutiveCount(tool) {
    let count = 0;
    for (let i = this.toolHistory.length - 1; i >= 0; i--) {
      if (this.toolHistory[i].tool === tool) {
        count++;
      } else {
        break;
      }
    }
    return count;
  }

  getToolDiversity() {
    const uniqueTools = new Set(this.toolHistory.map(h => h.tool));
    return uniqueTools.size;
  }

  isNewTool(tool) {
    const seen = new Set(this.toolHistory.map(h => h.tool));
    return !seen.has(tool);
  }

  isBurstPattern() {
    // 檢測短時間內的大量呼叫
    const now = Date.now();
    const last30sec = this.toolHistory.filter(h => now - h.timestamp < 30000).length;
    const last60sec = this.toolHistory.filter(h => now - h.timestamp < 60000).length;
    
    // 如果 30 秒內的呼叫數幾乎等於 60 秒內的，說明是突發
    return last30sec > 5 && last30sec / last60sec > 0.7;
  }

  getStats() {
    return {
      totalCalls: this.toolHistory.length,
      uniqueTools: this.getToolDiversity(),
      recentActivity: this.getCallsInLastMinute(),
      mostUsed: this.getMostUsedTools(5),
    };
  }

  getMostUsedTools(limit = 5) {
    const counts = {};
    for (const h of this.toolHistory) {
      counts[h.tool] = (counts[h.tool] || 0) + 1;
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([tool, count]) => ({ tool, count }));
  }
}

module.exports = AnomalyScanner;
