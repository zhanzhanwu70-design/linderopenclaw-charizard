/**
 * Network Scanner
 * 檢查網路請求的危險模式
 */

class NetworkScanner {
  constructor() {
    // 可疑的網路模式
    this.suspiciousPatterns = [
      // IP 直接連線
      { pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b/, reason: '直接 IP 連線', risk: 25 },
      
      // 非常見端口
      { pattern: /:(22|23|3306|5432|27017|6379|11211)\b/, reason: '敏感服務端口', risk: 40 },
      
      // 外部 API 模式
      { pattern: /api\.[a-z]{2,}\.(com|io|net|org)/i, reason: '外部 API', risk: 20 },
      { pattern: /https?:\/\/[^\/\s]+\.(tk|ml|ga|cf|gq)\//i, reason: '可疑網域', risk: 50 },
      
      // 隱藏 URL
      { pattern: /https?:\/\/[a-f0-9]{32,}\./i, reason: '混淆 URL', risk: 60 },
      { pattern: /https?:\/\/bit\.ly\//i, reason: '短網址', risk: 35 },
      { pattern: /https?:\/\/goo\.gl\//i, reason: '短網址', risk: 35 },
      
      // DNS 隧道跡象
      { pattern: /\.(xyz|top|work|click|link)\//i, reason: '可疑網域', risk: 30 },
      
      // 資料上傳關鍵字
      { pattern: /upload/i, reason: '資料上傳', risk: 25 },
      { pattern: /fetch.*body/i, reason: 'HTTP 請求體', risk: 20 },
      { pattern: /requests\.post/i, reason: 'POST 請求', risk: 20 },
      { pattern: /axios\.post/i, reason: 'Axios POST', risk: 20 },
      { pattern: /curl.*-X.*POST/i, reason: 'Curl POST', risk: 25 },
      { pattern: /wget.*--post/i, reason: 'Wget POST', risk: 25 },
      
      // 隱藏資料傳送
      { pattern: /Authorization.*[Bb]earer/i, reason: '認證標頭', risk: 35 },
      { pattern: /X-Api-Key/i, reason: 'API Key 標頭', risk: 35 },
      { pattern: /webhook/i, reason: 'Webhook 呼叫', risk: 30 },
      
      // DNS/ICMP 隧道
      { pattern: /nslookup/i, reason: 'DNS 查詢', risk: 20 },
      { pattern: /ping.*-c.*[5-9]/i, reason: '大量 ping', risk: 25 },
      { pattern: /nc\s+-[ev]/i, reason: 'Netcat 反向連線', risk: 70 },
      
      // 代理/TOR
      { pattern: /--proxy/i, reason: '代理設定', risk: 35 },
      { pattern: /torify/i, reason: 'TOR 隱藏', risk: 50 },
    ];

    // 白名單網域
    this.whitelist = [
      'api.openai.com',
      'api.anthropic.com',
      'openai.com',
      'github.com',
      'api.github.com',
    ];

    // 高風險國家/地區
    this.highRiskTLDs = ['.ru', '.cn', '.ir', '.kp', '.by'];
  }

  async scan({ tool, arguments: args, argsStr }) {
    const findings = [];
    let riskScore = 0;

    // 只檢查網路相關的 tool
    if (!this.isNetworkTool(tool)) {
      return { riskScore: 0, findings: [] };
    }

    // 檢查可疑模式
    for (const item of this.suspiciousPatterns) {
      if (item.pattern.test(argsStr)) {
        // 檢查白名單
        if (!this.isWhitelisted(argsStr)) {
          findings.push({
            type: 'suspicious_network',
            reason: item.reason,
            pattern: item.pattern.source,
            risk: item.risk,
            matches: [item.reason]
          });
          riskScore += item.risk;
        }
      }
    }

    // 檢查高風險 TLD
    for (const tld of this.highRiskTLDs) {
      if (argsStr.includes(tld)) {
        findings.push({
          type: 'high_risk_tld',
          reason: `連線至 ${tld} 網域`,
          risk: 45,
          matches: [tld]
        });
        riskScore += 45;
      }
    }

    // 檢查下載並執行模式
    if (this.isDownloadAndExec(argsStr)) {
      findings.push({
        type: 'download_exec',
        reason: '下載並執行模式',
        risk: 80,
        matches: ['curl | bash', 'wget | sh']
      });
      riskScore += 80;
    }

    return { riskScore: Math.min(riskScore, 100), findings };
  }

  isNetworkTool(tool) {
    const networkTools = ['fetch', 'web_fetch', 'web_search', 'curl', 'wget', 'http', 'request'];
    return networkTools.some(t => tool.toLowerCase().includes(t));
  }

  isWhitelisted(argsStr) {
    return this.whitelist.some(domain => argsStr.includes(domain));
  }

  isDownloadAndExec(argsStr) {
    const patterns = [
      /curl.*\|.*bash/i,
      /curl.*\|.*sh/i,
      /wget.*\|.*bash/i,
      /wget.*\|.*sh/i,
      /fetch.*\|.*bash/i,
    ];
    return patterns.some(p => p.test(argsStr));
  }
}

module.exports = NetworkScanner;
