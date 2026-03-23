/**
 * Security Scanner Hook
 * 在執行任何 tool 前自動掃描
 */

const FileSystemScanner = require('./scanners/file-system');
const NetworkScanner = require('./scanners/network');
const CommandExecScanner = require('./scanners/command-exec');
const PromptInjectionScanner = require('./scanners/prompt-injection');
const ToolChainScanner = require('./scanners/tool-chain');
const SensitiveDataScanner = require('./scanners/sensitive-data');
const AnomalyScanner = require('./scanners/anomaly');
const RiskAssessor = require('./core/risk-assessor');
const Logger = require('./core/logger');

class SecurityScannerHook {
  constructor(config = {}) {
    this.config = {
      thresholds: {
        safe: 20,
        low: 40,
        medium: 60,
        high: 80
      },
      blockOnHigh: true,
      logAllScans: true,
      ...config
    };

    this.scanners = {
      fileSystem: new FileSystemScanner(),
      network: new NetworkScanner(),
      commandExec: new CommandExecScanner(),
      promptInjection: new PromptInjectionScanner(),
      toolChain: new ToolChainScanner(),
      sensitiveData: new SensitiveDataScanner(),
      anomaly: new AnomalyScanner()
    };

    this.riskAssessor = new RiskAssessor(this.config.thresholds);
    this.logger = new Logger();

    // 執行歷史（用於異常偵測）
    this.executionHistory = [];
    this.maxHistorySize = 100;
  }

  /**
   * 主掃描方法 - 在 tool 執行前呼叫
   * @param {Object} toolCall - tool 呼叫資訊
   * @returns {Object} 掃描結果
   */
  async scan(toolCall) {
    const { name, arguments: args, sessionId } = toolCall;
    const argsStr = JSON.stringify(args);

    this.logger.info(`Scanning tool: ${name}`, { sessionId });

    const findings = [];
    let totalRiskScore = 0;

    // 並行執行所有掃描
    const scanPromises = Object.entries(this.scanners).map(async ([scannerName, scanner]) => {
      try {
        const result = await scanner.scan({ tool: name, arguments: args, argsStr });
        if (result.riskScore > 0) {
          findings.push({
            scanner: scannerName,
            ...result
          });
          totalRiskScore += result.riskScore;
        }
        return result;
      } catch (error) {
        this.logger.error(`Scanner ${scannerName} failed`, error);
        return { riskScore: 0, findings: [] };
      }
    });

    await Promise.all(scanPromises);

    // 更新執行歷史（用於異常偵測）
    this.updateHistory({ tool: name, timestamp: Date.now() });

    // 風險評估
    const assessment = this.riskAssessor.assess(totalRiskScore, findings);

    // 記錄結果
    this.logger.scanResult({
      tool: name,
      riskScore: totalRiskScore,
      level: assessment.level,
      score: totalRiskScore,
      findings: findings.length
    });

    // 根據風險等級決定行動
    return this.decideAction(assessment, toolCall, findings);
  }

  /**
   * 根據風險評估決定行動
   */
  decideAction(assessment, toolCall, findings) {
    const { level } = assessment;

    switch (level) {
      case 'safe':
      case 'low':
        return {
          allowed: true,
          level,
          message: 'Tool execution allowed',
          findings
        };

      case 'medium':
        return {
          allowed: true,
          level,
          message: 'Tool execution allowed with warning',
          findings,
          requiresReview: true
        };

      case 'high':
        if (this.config.blockOnHigh) {
          return {
            allowed: false,
            level,
            message: 'Tool blocked - high risk detected',
            findings,
            reason: this.summarizeReason(findings)
          };
        }
        return {
          allowed: true,
          level,
          message: 'Tool execution allowed - HIGH RISK WARNING',
          findings,
          requiresConfirmation: true
        };

      case 'critical':
        return {
          allowed: false,
          level,
          message: 'Tool blocked - critical risk detected',
          findings,
          reason: this.summarizeReason(findings),
          quarantined: true
        };

      default:
        return {
          allowed: false,
          level: 'unknown',
          message: 'Tool blocked - unable to assess risk',
          findings
        };
    }
  }

  /**
   * 總結風險原因
   */
  summarizeReason(findings) {
    return findings
      .filter(f => f.riskScore >= 20)
      .map(f => f.reason || `${f.scanner}: ${f.matches?.join(', ')}`)
      .join('; ');
  }

  /**
   * 更新執行歷史
   */
  updateHistory(entry) {
    this.executionHistory.push(entry);
    if (this.executionHistory.length > this.maxHistorySize) {
      this.executionHistory.shift();
    }
  }

  /**
   * 獲取執行統計
   */
  getStats() {
    return {
      totalScans: this.executionHistory.length,
      recentTools: this.executionHistory.slice(-10).map(e => e.tool),
      blockedCount: 0, // 可從 logger 取得
    };
  }
}

module.exports = SecurityScannerHook;
