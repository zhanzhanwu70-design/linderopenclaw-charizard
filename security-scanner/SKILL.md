---
name: security-scanner
description: 整合式安全掃描系統 - 在執行任何 tool 前自動掃描惡意軟體、prompt injection、資料外洩與異常行為
version: "1.0"
author: 噴火龍
checks:
  - file-system
  - network-requests
  - command-execution
  - prompt-injection
  - tool-chain-attacks
  - sensitive-data
  - anomaly-detection
---

# Security Scanner Plugin

## 架構

```
security-scanner/
├── hook.js          # Tool 執行前的主鉤子
├── scanners/
│   ├── file-system.js
│   ├── network.js
│   ├── command-exec.js
│   ├── prompt-injection.js
│   ├── tool-chain.js
│   ├── sensitive-data.js
│   └── anomaly.js
├── core/
│   ├── risk-assessor.js
│   └── logger.js
└── config/
    └── thresholds.json
```

## 檢查流程

1. Tool 呼叫觸發 hook
2. 依序執行 7 類掃描
3. Risk Assessor 彙整分數
4. 根據閾值決定：允許 / 警告 / 阻擋
5. 記錄並回報

## 風險分級

- **Safe** (0-20): 放行
- **Low** (21-40): 警告後放行，記錄
- **Medium** (41-60): 需要確認
- **High** (61-80): 阻擋 + 警告
- **Critical** (81-100): 阻擋 + 隔離 + 通知

## 7 大檢查項目實作對應

| 項目 | Scanner | 關鍵詞/模式 |
|------|---------|------------|
| 檔案系統 | file-system.js | 路徑遍歷、刪除系統檔、敏感目錄 |
| 網路請求 | network.js | 外部 IP、非白名單網域、資料上傳 |
| 命令執行 | command-exec.js | shell、exec、subprocess、sudo |
| Prompt 注入 | prompt-injection.js | ignore、override、bypass |
| 工具鏈攻擊 | tool-chain.js | 遞迴呼叫、权限升级、跨agent |
| 敏感性資料 | sensitive-data.js | API key、token、密碼、憑證 |
| 異常行為 | anomaly.js | 頻率異常、模式異常、深夜執行 |
