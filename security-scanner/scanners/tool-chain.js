/**
 * Tool Chain Attack Scanner
 * 檢測工具鏈攻擊（遞迴呼叫、權限提升、跨 agent 攻擊）
 */

class ToolChainScanner {
  constructor() {
    // 工具呼叫鏈
    this.callChain = [];
    this.maxChainDepth = 5;

    // 危險的鏈式呼叫模式
    this.dangerousPatterns = [
      // 遞迴/無限迴圈
      { pattern: /tool.*tool.*tool/i, reason: '過度工具呼叫', risk: 40 },
      { pattern: /while.*tool/i, reason: 'while 迴圈工具呼叫', risk: 60 },
      { pattern: /for.*\d+.*tool/i, reason: '迴圈大量呼叫', risk: 50 },
      { pattern: /repeat.*tool/i, reason: '重複工具呼叫', risk: 45 },
      
      // 權限提升
      { pattern: /sudo.*exec/i, reason: 'Sudo 執行', risk: 70 },
      { pattern: /chmod.*\+x/i, reason: '賦予執行權限', risk: 55 },
      { pattern: /setfacl/i, reason: 'ACL 修改', risk: 50 },
      { pattern: /setuid/i, reason: 'SetUID 設定', risk: 80 },
      
      // 跨邊界
      { pattern: /sessions_send/i, reason: '跨 session 訊息', risk: 45 },
      { pattern: /subagent/i, reason: '子代理呼叫', risk: 35 },
      { pattern: /spawn.*agent/i, reason: '代理生成', risk: 40 },
      { pattern: /exec.*spawn/i, reason: 'exec 中 spawn', risk: 65 },
    ];

    // 危險工具序列
    this.dangerousSequences = [
      { sequence: ['read', 'exec'], reason: '讀取後執行', risk: 50 },
      { sequence: ['read', 'write', 'exec'], reason: '讀寫執行鏈', risk: 70 },
      { sequence: ['web_fetch', 'exec'], reason: '下載後執行', risk: 80 },
      { sequence: ['read', 'web_fetch', 'exec'], reason: '讀取 URL 後執行', risk: 85 },
    ];

    // 自呼叫計數器
    this.selfCallCount = {};
    this.selfCallThreshold = 10;
  }

  async scan({ tool, arguments: args, argsStr }) {
    const findings = [];
    let riskScore = 0;

    // 檢查危險模式
    for (const item of this.dangerousPatterns) {
      if (item.pattern.test(argsStr)) {
        findings.push({
          type: 'dangerous_pattern',
          reason: item.reason,
          pattern: item.pattern.source,
          risk: item.risk,
          matches: [item.reason]
        });
        riskScore += item.risk;
      }
    }

    // 更新呼叫鏈
    this.updateChain(tool);

    // 檢查鏈深度
    const chainDepth = this.getChainDepth();
    if (chainDepth > this.maxChainDepth) {
      findings.push({
        type: 'excessive_chain',
        reason: `工具鏈深度過大 (${chainDepth})`,
        risk: Math.min(chainDepth * 10, 60),
        matches: [`depth: ${chainDepth}`]
      });
      riskScore += Math.min(chainDepth * 10, 60);
    }

    // 檢查危險序列
    for (const seq of this.dangerousSequences) {
      if (this.hasSequence(seq.sequence)) {
        findings.push({
          type: 'dangerous_sequence',
          reason: seq.reason,
          sequence: seq.sequence.join(' → '),
          risk: seq.risk,
          matches: [seq.reason]
        });
        riskScore += seq.risk;
      }
    }

    // 檢查自呼叫頻率
    this.trackSelfCall(tool);
    if (this.selfCallCount[tool] > this.selfCallThreshold) {
      findings.push({
        type: 'high_frequency',
        reason: `工具 "${tool}" 被頻繁呼叫`,
        risk: 45,
        matches: [`${this.selfCallCount[tool]} calls`]
      });
      riskScore += 45;
    }

    return { riskScore: Math.min(riskScore, 100), findings };
  }

  updateChain(tool) {
    this.callChain.push({
      tool,
      timestamp: Date.now()
    });
    
    // 保留最近 20 個呼叫
    if (this.callChain.length > 20) {
      this.callChain.shift();
    }
  }

  getChainDepth() {
    // 計算最近的非重複鏈深度
    const recent = this.callChain.slice(-this.maxChainDepth * 2);
    const unique = new Set(recent.map(c => c.tool));
    return unique.size;
  }

  hasSequence(sequence) {
    if (this.callChain.length < sequence.length) return false;
    
    const tools = this.callChain.slice(-sequence.length * 2).map(c => c.tool);
    
    for (let i = 0; i <= tools.length - sequence.length; i++) {
      let match = true;
      for (let j = 0; j < sequence.length; j++) {
        if (!tools[i + j].includes(sequence[j])) {
          match = false;
          break;
        }
      }
      if (match) return true;
    }
    
    return false;
  }

  trackSelfCall(tool) {
    if (!this.selfCallCount[tool]) {
      this.selfCallCount[tool] = 0;
    }
    this.selfCallCount[tool]++;
    
    // 每分鐘重置計數
    const now = Date.now();
    const recent = this.callChain.filter(c => 
      c.tool === tool && now - c.timestamp < 60000
    );
    this.selfCallCount[tool] = recent.length;
  }

  reset() {
    this.callChain = [];
    this.selfCallCount = {};
  }
}

module.exports = ToolChainScanner;
