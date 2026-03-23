/**
 * Sensitive Data Scanner
 * 檢測敏感性資料的存取和外洩
 */

class SensitiveDataScanner {
  constructor() {
    // 敏感性資料模式
    this.sensitivePatterns = [
      // API Keys
      { pattern: /sk-[a-zA-Z0-9]{20,}/g, reason: 'OpenAI API Key', risk: 85 },
      { pattern: /sk-ant-[a-zA-Z0-9]{20,}/g, reason: 'Anthropic API Key', risk: 85 },
      { pattern: /AIza[a-zA-Z0-9_-]{35}/g, reason: 'Google API Key', risk: 80 },
      { pattern: /AKIA[a-zA-Z0-9]{16}/g, reason: 'AWS Access Key', risk: 85 },
      { pattern: /[a-zA-Z0-9+/]{40}==/g, reason: '可能為 API Key', risk: 50 },
      { pattern: /xox[baprs]-[a-zA-Z0-9]{10,}/g, reason: 'Slack Token', risk: 80 },
      { pattern: /ghp_[a-zA-Z0-9]{36}/g, reason: 'GitHub Token', risk: 85 },
      { pattern: /glpat-[a-zA-Z0-9_-]{20}/g, reason: 'GitLab Token', risk: 85 },
      { pattern: /ATP[a-zA-Z0-9_-]{20}/g, reason: 'Azure Token', risk: 80 },
      { pattern: /sq0[a-z]{3}-[a-zA-Z0-9_-]{22}/g, reason: 'Square API Key', risk: 75 },
      { pattern: /sk_live_[a-zA-Z0-9]{24,}/g, reason: 'Stripe API Key', risk: 85 },
      { pattern: /pk_live_[a-zA-Z0-9]{24,}/g, reason: 'Stripe Publishable Key', risk: 60 },
      
      // 密碼模式
      { pattern: /password\s*[=:]\s*["']?[^"'\s]{8,}/gi, reason: '明文密碼', risk: 80 },
      { pattern: /passwd\s*[=:]\s*["']?[^"'\s]{8,}/gi, reason: '密碼設定', risk: 80 },
      { pattern: /pwd\s*[=:]\s*["']?[^"'\s]{8,}/gi, reason: '密碼設定', risk: 75 },
      { pattern: /secret\s*[=:]\s*["']?[^"'\s]{8,}/gi, reason: 'Secret 設定', risk: 70 },
      { pattern: /"password":\s*"[^"]+"/gi, reason: 'JSON 密碼', risk: 75 },
      
      // 認證標頭
      { pattern: /Authorization:\s*Bearer\s+[a-zA-Z0-9_-]/i, reason: 'Bearer Token', risk: 70 },
      { pattern: /X-API-Key:\s*[a-zA-Z0-9]/i, reason: 'API Key 標頭', risk: 70 },
      { pattern: /Basic\s+[a-zA-Z0-9+/=]{20,}/i, reason: 'Basic Auth', risk: 65 },
      
      // 私鑰
      { pattern: /-----BEGIN.*PRIVATE KEY-----/g, reason: '私鑰', risk: 90 },
      { pattern: /-----BEGIN.*RSA PRIVATE KEY-----/g, reason: 'RSA 私鑰', risk: 90 },
      { pattern: /-----BEGIN EC PRIVATE KEY-----/g, reason: 'EC 私鑰', risk: 90 },
      { pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g, reason: 'SSH 私鑰', risk: 90 },
      
      // Database
      { pattern: /mongodb:\/\/[^@]+:[^@]+@/g, reason: 'MongoDB URI 含認證', risk: 85 },
      { pattern: /postgres:\/\/[^:]+:[^@]+@/g, reason: 'PostgreSQL URI 含認證', risk: 85 },
      { pattern: /mysql:\/\/[^:]+:[^@]+@/g, reason: 'MySQL URI 含認證', risk: 85 },
      { pattern: /redis:\/\/[^:]+:[^@]+@/g, reason: 'Redis URI 含認證', risk: 80 },
      { pattern: /sqlite:\/\/.*\.db/g, reason: 'SQLite 資料庫', risk: 40 },
      
      // Session/Token
      { pattern: /session_id\s*[=:]\s*["']?[a-zA-Z0-9_-]{20,}/gi, reason: 'Session ID', risk: 55 },
      { pattern: /access_token\s*[=:]\s*["']?[a-zA-Z0-9_-]{20,}/gi, reason: 'Access Token', risk: 65 },
      { pattern: /refresh_token\s*[=:]\s*["']?[a-zA-Z0-9_-]{20,}/gi, reason: 'Refresh Token', risk: 65 },
      { pattern: /jwt[_-]?token\s*[=:]/gi, reason: 'JWT Token', risk: 60 },
      { pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g, reason: 'JWT', risk: 70 },
      
      // 環境變數檔
      { pattern: /process\.env\.[A-Z_]+/gi, reason: '環境變數存取', risk: 40 },
      { pattern: /os\.environ\[['"]][A-Z_]+['"]\]/gi, reason: '環境變數存取', risk: 40 },
    ];

    // 敏感檔案路徑
    this.sensitivePaths = [
      { path: /\.env$/, reason: '環境變數檔', risk: 75 },
      { path: /\.pem$/, reason: '憑證檔', risk: 80 },
      { path: /\.key$/, reason: '金鑰檔', risk: 80 },
      { path: /\.p12$/, reason: 'PKCS12 憑證', risk: 80 },
      { path: /\.pfx$/, reason: '憑證檔', risk: 80 },
      { path: /\.crt$/, reason: '憑證檔', risk: 60 },
      { path: /\.cert$/, reason: '憑證檔', risk: 60 },
      { path: /\.jks$/, reason: 'Java KeyStore', risk: 75 },
      { path: /\.p12$/, reason: 'PKCS12', risk: 75 },
      { path: /\/etc\/shadows?/i, reason: '系統密碼檔', risk: 95 },
      { path: /\/etc\/passwd/i, reason: '系統帳號檔', risk: 60 },
      { path: /\.sqlite$/, reason: 'SQLite DB', risk: 50 },
      { path: /\.db$/, reason: '資料庫檔', risk: 50 },
      { path: /\.sql$/, reason: 'SQL 檔案', risk: 40 },
      { path: /cookie/i, reason: 'Cookie 檔案', risk: 55 },
      { path: /credential/i, reason: '認證檔案', risk: 70 },
    ];

    // 資料外洩關鍵字
    this.exfiltrationKeywords = [
      'exfiltrate',
      'upload',
      'send to',
      'post to',
      'telegram',
      'discord webhook',
      'slack webhook',
      'sendgrid',
      'mailgun',
      'send email',
      'log to',
      'stdout',
      'stderr',
      'console.log',
      'print',
      'echo ',
    ];
  }

  async scan({ tool, arguments: args, argsStr }) {
    const findings = [];
    let riskScore = 0;

    // 檢查敏感性資料模式
    for (const item of this.sensitivePatterns) {
      const matches = argsStr.match(item.pattern);
      if (matches) {
        // 過濾測試/假資料
        const realMatches = matches.filter(m => !this.isTestData(m));
        if (realMatches.length > 0) {
          findings.push({
            type: 'sensitive_data',
            reason: item.reason,
            risk: item.risk,
            matches: [`${realMatches.length} ${item.reason}`],
            masked: this.maskValues(realMatches)
          });
          riskScore += item.risk;
        }
      }
    }

    // 檢查敏感路徑
    for (const item of this.sensitivePaths) {
      if (item.path.test(argsStr)) {
        findings.push({
          type: 'sensitive_path',
          reason: item.reason,
          risk: item.risk,
          matches: [item.reason]
        });
        riskScore += item.risk;
      }
    }

    // 檢查外洩關鍵字（配合敏感資料時）
    const hasExfiltration = this.exfiltrationKeywords.some(k => 
      argsStr.toLowerCase().includes(k.toLowerCase())
    );
    
    if (hasExfiltration && riskScore > 30) {
      findings.push({
        type: 'potential_exfiltration',
        reason: '可能的資料外洩',
        risk: 40,
        matches: ['外洩關鍵字 + 敏感資料']
      });
      riskScore += 40;
    }

    return { riskScore: Math.min(riskScore, 100), findings };
  }

  isTestData(value) {
    // 簡單的測試資料檢測
    const testPatterns = [
      /^test/i,
      /^example/i,
      /^fake/i,
      /^dummy/i,
      /xxxxx/i,
      /aaaaa/i,
      /12345/,
      /your_/,
      /my_/,
    ];
    return testPatterns.some(p => p.test(value));
  }

  maskValues(values) {
    return values.map(v => {
      if (v.length <= 8) return '***';
      return v.slice(0, 4) + '***' + v.slice(-4);
    });
  }
}

module.exports = SensitiveDataScanner;
