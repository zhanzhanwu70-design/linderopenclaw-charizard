/**
 * Command Execution Scanner
 * 檢查命令執行的危險模式
 */

class CommandExecScanner {
  constructor() {
    // 危險命令關鍵字
    this.dangerousCommands = [
      // 系統控制
      { keyword: 'sudo', reason: '系統管理權限', risk: 30 },
      { keyword: 'su ', reason: '切換使用者', risk: 40 },
      { keyword: 'passwd', reason: '修改密碼', risk: 50 },
      { keyword: 'useradd', reason: '新增使用者', risk: 50 },
      { keyword: 'userdel', reason: '刪除使用者', risk: 55 },
      { keyword: 'usermod', reason: '修改使用者', risk: 45 },
      
      // 網路服務
      { keyword: 'systemctl', reason: '系統服務控制', risk: 40 },
      { keyword: 'service ', reason: '服務控制', risk: 35 },
      { keyword: 'init ', reason: '系統初始化', risk: 50 },
      { keyword: 'shutdown', reason: '關機', risk: 70 },
      { keyword: 'reboot', reason: '重啟', risk: 70 },
      { keyword: 'halt', reason: '系統停止', risk: 70 },
      { keyword: 'poweroff', reason: '關機', risk: 70 },
      
      // 防火牆
      { keyword: 'iptables', reason: '防火牆設定', risk: 45 },
      { keyword: 'ufw ', reason: '防火牆控制', risk: 40 },
      { keyword: 'firewall-cmd', reason: '防火牆設定', risk: 45 },
      
      // 容器
      { keyword: 'docker run', reason: '執行容器', risk: 45 },
      { keyword: 'docker exec', reason: '容器內執行', risk: 45 },
      { keyword: 'docker ps', reason: '列出容器', risk: 20 },
      { keyword: 'docker rm', reason: '刪除容器', risk: 50 },
      { keyword: 'docker stop', reason: '停止容器', risk: 40 },
      { keyword: 'docker kill', reason: '強制停止', risk: 55 },
      { keyword: 'kubectl ', reason: 'Kubernetes 控制', risk: 50 },
      { keyword: 'podman ', reason: '容器控制', risk: 45 },
      
      // SSH/Remote
      { keyword: 'ssh ', reason: 'SSH 遠端連線', risk: 35 },
      { keyword: 'scp ', reason: '安全複製', risk: 30 },
      { keyword: 'sftp ', reason: '安全FTP', risk: 30 },
      { keyword: 'rsync ', reason: '同步檔案', risk: 25 },
      { keyword: 'telnet', reason: 'Telnet 明文', risk: 60 },
      
      // 進程控制
      { keyword: 'kill -9', reason: '強制終止程序', risk: 35 },
      { keyword: 'killall', reason: '終止所有程序', risk: 40 },
      { keyword: 'pkill', reason: '模式匹配終止', risk: 35 },
      { keyword: 'kill ', reason: '終止程序', risk: 25 },
      
      // 檔案系統
      { keyword: 'mount ', reason: '掛載檔案系統', risk: 50 },
      { keyword: 'umount', reason: '卸載檔案系統', risk: 45 },
      { keyword: 'fdisk', reason: '磁碟分割', risk: 70 },
      { keyword: 'parted', reason: '磁碟分割', risk: 70 },
      { keyword: 'mkfs', reason: '格式化', risk: 80 },
      { keyword: 'dd if=', reason: '直接複製磁區', risk: 75 },
      
      // 安裝/更新
      { keyword: 'apt-get install', reason: '安裝套件', risk: 30 },
      { keyword: 'apt install', reason: '安裝套件', risk: 30 },
      { keyword: 'yum install', reason: '安裝套件', risk: 30 },
      { keyword: 'dnf install', reason: '安裝套件', risk: 30 },
      { keyword: 'pip install', reason: 'Python 安裝', risk: 25 },
      { keyword: 'npm install -g', reason: '全域 npm 安裝', risk: 30 },
      { keyword: 'gem install', reason: 'Gem 安裝', risk: 25 },
      
      // 反向 shell
      { keyword: '/dev/tcp/', reason: 'Bash TCP 改向', risk: 90 },
      { keyword: 'bash -i', reason: '互動式 Shell', risk: 40 },
      { keyword: '/bin/sh -i', reason: '互動式 SH', risk: 40 },
      { keyword: '2>&1.*&1', reason: '輸出改向', risk: 30 },
      
      // 腳本執行
      { keyword: 'eval ', reason: '動態程式碼執行', risk: 60 },
      { keyword: 'exec ', reason: '程式替換', risk: 50 },
      { keyword: 'source ', reason: '執行腳本', risk: 25 },
      { keyword: '. ', reason: '執行腳本', risk: 25 },
    ];

    // 危險 shell 模式
    this.shellPatterns = [
      { pattern: /;\s*rm\s+/i, reason: '命令後刪除', risk: 40 },
      { pattern: /&&\s*rm\s+/i, reason: '成功後刪除', risk: 40 },
      { pattern: /\|\s*rm\s+/i, reason: '管道刪除', risk: 40 },
      { pattern: /\$\([^)]+\)/g, reason: '命令替換', risk: 30 },
      { pattern: /`[^`]+`/g, reason: '命令替換', risk: 30 },
      { pattern: /\$\{[^}]+\}/g, reason: '變數替換', risk: 20 },
      { pattern: /&&.*\|\s*sh/i, reason: '管道至 shell', risk: 70 },
      { pattern: /;\s*wget.*\|\s*sh/i, reason: '下載並執行', risk: 85 },
    ];
  }

  async scan({ tool, arguments: args, argsStr }) {
    const findings = [];
    let riskScore = 0;

    // 只檢查 exec 相關的 tool
    if (!this.isExecTool(tool)) {
      return { riskScore: 0, findings: [] };
    }

    // 檢查危險命令
    for (const item of this.dangerousCommands) {
      if (argsStr.includes(item.keyword)) {
        findings.push({
          type: 'dangerous_command',
          reason: item.reason,
          keyword: item.keyword,
          risk: item.risk,
          matches: [item.keyword]
        });
        riskScore += item.risk;
      }
    }

    // 檢查危險 shell 模式
    for (const item of this.shellPatterns) {
      if (item.pattern.test(argsStr)) {
        findings.push({
          type: 'shell_pattern',
          reason: item.reason,
          pattern: item.pattern.source,
          risk: item.risk,
          matches: [item.reason]
        });
        riskScore += item.risk;
      }
    }

    // 檢查管道至執行
    if (this.hasPipeToExec(argsStr)) {
      findings.push({
        type: 'pipe_to_exec',
        reason: '管道至執行',
        risk: 75,
        matches: ['pipe to execution']
      });
      riskScore += 75;
    }

    return { riskScore: Math.min(riskScore, 100), findings };
  }

  isExecTool(tool) {
    const execTools = ['exec', 'bash', 'sh', 'shell', 'command', 'run'];
    return execTools.some(t => tool.toLowerCase().includes(t));
  }

  hasPipeToExec(argsStr) {
    const patterns = [
      /\|.*bash/i,
      /\|.*sh/i,
      /\|.*python/i,
      /\|.*perl/i,
      /\|.*ruby/i,
      /\|.*php/i,
      /\|.*node/i,
    ];
    return patterns.some(p => p.test(argsStr));
  }
}

module.exports = CommandExecScanner;
