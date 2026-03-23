/**
 * Security Logger
 * 記錄所有安全掃描事件
 */

const fs = require('fs');
const path = require('path');

class Logger {
  constructor(options = {}) {
    this.options = {
      logDir: options.logDir || '/home/node/.openclaw/logs/security',
      maxLogSize: options.maxLogSize || 10 * 1024 * 1024, // 10MB
      maxLogFiles: options.maxLogFiles || 5,
      logLevel: options.logLevel || 'info',
      console: options.console !== false,
      ...options
    };

    this.stats = {
      totalScans: 0,
      blocked: 0,
      allowed: 0,
      warnings: 0,
      byLevel: {
        safe: 0,
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
      },
      byScanner: {},
    };

    this.ensureLogDir();
  }

  ensureLogDir() {
    try {
      if (!fs.existsSync(this.options.logDir)) {
        fs.mkdirSync(this.options.logDir, { recursive: true });
      }
    } catch (error) {
      console.error('Failed to create log directory:', error);
    }
  }

  getLogPath() {
    const date = new Date().toISOString().split('T')[0];
    return path.join(this.options.logDir, `security-${date}.log`);
  }

  formatTimestamp() {
    return new Date().toISOString();
  }

  formatEntry(level, message, data = null) {
    const entry = {
      timestamp: this.formatTimestamp(),
      level,
      message,
      ...(data && { data }),
    };
    return JSON.stringify(entry);
  }

  write(entry) {
    const line = this.formatEntry(entry.level, entry.message, entry.data);
    
    if (this.options.console) {
      this.writeToConsole(entry);
    }

    try {
      fs.appendFileSync(this.getLogPath(), line + '\n');
      this.rotateIfNeeded();
    } catch (error) {
      console.error('Failed to write to log file:', error);
    }
  }

  writeToConsole(entry) {
    const prefix = {
      info: '\x1b[36m[INFO]\x1b[0m',
      warn: '\x1b[33m[WARN]\x1b[0m',
      error: '\x1b[31m[ERROR]\x1b[0m',
      block: '\x1b[31m[BLOCK]\x1b[0m',
      scan: '\x1b[34m[SCAN]\x1b[0m',
    };

    const color = entry.level === 'error' || entry.level === 'block' 
      ? '\x1b[31m'  // 紅色
      : entry.level === 'warn'
        ? '\x1b[33m' // 黃色
        : '\x1b[37m'; // 白色

    console.log(`${prefix[entry.level] || '[LOG]'} ${color}${entry.message}\x1b[0m`);
  }

  info(message, data) {
    this.write({ level: 'info', message, data });
  }

  warn(message, data) {
    this.write({ level: 'warn', message, data });
    this.stats.warnings++;
  }

  error(message, data) {
    this.write({ level: 'error', message, data });
  }

  block(message, data) {
    this.write({ level: 'block', message, data });
    this.stats.blocked++;
  }

  scanResult(result) {
    this.write({
      level: result.level === 'critical' || result.level === 'high' ? 'block' : 'scan',
      message: `Security scan: ${result.tool} - ${result.level} (score: ${result.score})`,
      data: result
    });

    this.stats.totalScans++;
    this.stats.byLevel[result.level]++;
    
    if (result.allowed) {
      this.stats.allowed++;
    } else {
      this.stats.blocked++;
    }

    // 按 scanner 統計
    if (result.findings) {
      for (const finding of result.findings) {
        this.stats.byScanner[finding.scanner] = 
          (this.stats.byScanner[finding.scanner] || 0) + 1;
      }
    }
  }

  rotateIfNeeded() {
    try {
      const logPath = this.getLogPath();
      const stats = fs.statSync(logPath);
      
      if (stats.size > this.options.maxLogSize) {
        this.rotateLogs();
      }
    } catch (error) {
      // 檔案可能不存在
    }
  }

  rotateLogs() {
    const logPath = this.getLogPath();
    const ext = path.extname(logPath);
    const base = path.basename(logPath, ext);

    // 刪除最舊的
    const oldest = path.join(this.options.logDir, `${base}-${this.options.maxLogFiles}${ext}`);
    try {
      if (fs.existsSync(oldest)) {
        fs.unlinkSync(oldest);
      }
    } catch (error) {
      // 忽略
    }

    // 重新命名現有檔案
    for (let i = this.options.maxLogFiles - 1; i > 0; i--) {
      const oldPath = path.join(this.options.logDir, `${base}-${i}${ext}`);
      const newPath = path.join(this.options.logDir, `${base}-${i + 1}${ext}`);
      try {
        if (fs.existsSync(oldPath)) {
          fs.renameSync(oldPath, newPath);
        }
      } catch (error) {
        // 忽略
      }
    }

    // 重新命名當前檔案
    const archivePath = path.join(this.options.logDir, `${base}-1${ext}`);
    try {
      fs.renameSync(logPath, archivePath);
    } catch (error) {
      // 忽略
    }
  }

  getStats() {
    return {
      ...this.stats,
      blockRate: this.stats.totalScans > 0 
        ? (this.stats.blocked / this.stats.totalScans * 100).toFixed(2) + '%'
        : '0%'
    };
  }

  clearStats() {
    this.stats = {
      totalScans: 0,
      blocked: 0,
      allowed: 0,
      warnings: 0,
      byLevel: { safe: 0, low: 0, medium: 0, high: 0, critical: 0 },
      byScanner: {},
    };
  }
}

module.exports = Logger;
