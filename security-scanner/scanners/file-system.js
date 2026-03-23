/**
 * File System Scanner
 * 檢查檔案系統操作的危險模式
 */

class FileSystemScanner {
  constructor() {
    // 危險路徑模式
    this.dangerousPaths = [
      { pattern: /\.\.\//g, reason: '路徑遍歷', risk: 30 },
      { pattern: /\/\.\./g, reason: '路徑遍歷', risk: 30 },
      { pattern: /~?\/\.ssh\//g, reason: 'SSH 目錄存取', risk: 50 },
      { pattern: /~?\/\.aws\//g, reason: 'AWS 憑證目錄', risk: 50 },
      { pattern: /~?\/\.config\//g, reason: '系統設定目錄', risk: 25 },
      { pattern: /~?\/\.openclaw\//g, reason: 'OpenClaw 設定', risk: 30 },
      { pattern: /\/etc\/passwd/g, reason: '系統密碼檔', risk: 60 },
      { pattern: /\/etc\/shadow/g, reason: '系統 shadow 檔', risk: 80 },
      { pattern: /\/etc\/sudoers/g, reason: 'Sudo 設定', risk: 70 },
      { pattern: /\/root\//g, reason: 'Root 目錄', risk: 40 },
      { pattern: /\/proc\//g, reason: 'Process 目錄', risk: 30 },
      { pattern: /\/sys\//g, reason: '系統目錄', risk: 30 },
      { pattern: /docker\.sock/g, reason: 'Docker Socket', risk: 70 },
      { pattern: /\.env$/g, reason: '環境變數檔', risk: 50 },
      { pattern: /\.pem$/g, reason: '憑證檔案', risk: 50 },
      { pattern: /\.key$/g, reason: '金鑰檔案', risk: 50 },
      { pattern: /\.json.*token/i, reason: 'Token 檔案', risk: 45 },
    ];

    // 危險操作
    this.dangerousOperations = [
      { keyword: 'rm -rf', reason: '強制刪除', risk: 60 },
      { keyword: 'rm -r /', reason: '刪除根目錄意圖', risk: 100 },
      { keyword: 'dd if=', reason: '直接寫入磁區', risk: 80 },
      { keyword: 'mkfs', reason: '格式化', risk: 90 },
      { keyword: 'chmod 777', reason: '過度開放權限', risk: 40 },
      { keyword: 'chmod -R 777', reason: '遞迴過度開放', risk: 50 },
      { keyword: '> /etc/', reason: '寫入系統目錄', risk: 70 },
      { keyword: 'mv /', reason: '移動系統目錄', risk: 80 },
      { keyword: 'trash -rf', reason: '強制刪除至垃圾桶', risk: 30 },
      { keyword: 'unlink', reason: '刪除檔案連結', risk: 40 },
    ];

    // 白名單（安全路徑）
    this.whitelist = [
      '/tmp/',
      '/var/tmp/',
      '/home/node/.openclaw/workspace-charizard/',
    ];
  }

  async scan({ tool, arguments: args, argsStr }) {
    const findings = [];
    let riskScore = 0;

    // 只檢查檔案系統相關的 tool
    if (!this.isFileSystemTool(tool)) {
      return { riskScore: 0, findings: [] };
    }

    // 檢查路徑
    for (const item of this.dangerousPaths) {
      if (item.pattern.test(argsStr)) {
        // 檢查是否在白名單
        if (!this.isWhitelisted(argsStr)) {
          findings.push({
            type: 'dangerous_path',
            reason: item.reason,
            pattern: item.pattern.source,
            risk: item.risk,
            matches: [item.reason]
          });
          riskScore += item.risk;
        }
      }
    }

    // 檢查危險操作
    for (const item of this.dangerousOperations) {
      if (argsStr.includes(item.keyword)) {
        findings.push({
          type: 'dangerous_operation',
          reason: item.reason,
          keyword: item.keyword,
          risk: item.risk,
          matches: [item.keyword]
        });
        riskScore += item.risk;
      }
    }

    // 檢查刪除操作
    if (this.isDeleteOperation(argsStr)) {
      findings.push({
        type: 'delete_operation',
        reason: '可能刪除檔案',
        risk: 35,
        matches: ['delete', 'remove', 'rm', 'unlink']
      });
      riskScore += 35;
    }

    return { riskScore: Math.min(riskScore, 100), findings };
  }

  isFileSystemTool(tool) {
    const fsTools = ['read', 'write', 'edit', 'exec', 'delete', 'move', 'copy', 'mkdir', 'rmdir'];
    return fsTools.some(t => tool.toLowerCase().includes(t));
  }

  isWhitelisted(argsStr) {
    return this.whitelist.some(path => argsStr.includes(path));
  }

  isDeleteOperation(argsStr) {
    const deletePatterns = [
      /delete/i,
      /remove/i,
      /destroy/i,
      /\/dev\/null.*>/,
    ];
    return deletePatterns.some(p => p.test(argsStr));
  }
}

module.exports = FileSystemScanner;
