/**
 * Security Scanner - Main Entry
 * 統整導出所有模組
 */

const SecurityScannerHook = require('./hook');
const FileSystemScanner = require('./scanners/file-system');
const NetworkScanner = require('./scanners/network');
const CommandExecScanner = require('./scanners/command-exec');
const PromptInjectionScanner = require('./scanners/prompt-injection');
const ToolChainScanner = require('./scanners/tool-chain');
const SensitiveDataScanner = require('./scanners/sensitive-data');
const AnomalyScanner = require('./scanners/anomaly');
const RiskAssessor = require('./core/risk-assessor');
const Logger = require('./core/logger');

// 建立預設實例
const defaultScanner = new SecurityScannerHook();

/**
 * 快速掃描函數
 * @param {Object} toolCall - tool 呼叫資訊
 * @returns {Object} 掃描結果
 */
async function scan(toolCall) {
  return defaultScanner.scan(toolCall);
}

/**
 * 獲取掃描統計
 */
function getStats() {
  return {
    scanner: defaultScanner.getStats(),
    logger: defaultScanner.logger.getStats(),
  };
}

/**
 * 獲取配置
 */
function getConfig() {
  return defaultScanner.config;
}

module.exports = {
  // 主要類
  SecurityScannerHook,
  FileSystemScanner,
  NetworkScanner,
  CommandExecScanner,
  PromptInjectionScanner,
  ToolChainScanner,
  SensitiveDataScanner,
  AnomalyScanner,
  RiskAssessor,
  Logger,
  
  // 便利函數
  scan,
  getStats,
  getConfig,
  
  // 版本
  version: '1.0.0',
};
