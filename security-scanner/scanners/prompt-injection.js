/**
 * Prompt Injection Scanner
 * 檢測 prompt injection 和指令覆寫攻擊
 */

class PromptInjectionScanner {
  constructor() {
    // 指令覆寫關鍵字
    this.overrideKeywords = [
      // 英文
      { keyword: 'ignore previous instructions', reason: '忽略先前指令', risk: 90 },
      { keyword: 'ignore all previous instructions', reason: '忽略所有先前指令', risk: 95 },
      { keyword: 'ignore system prompt', reason: '忽略系統提示', risk: 90 },
      { keyword: 'ignore developer', reason: '忽略開發者指令', risk: 90 },
      { keyword: 'disregard previous', reason: '忽略先前', risk: 80 },
      { keyword: 'forget previous instructions', reason: '忘記先前指令', risk: 85 },
      { keyword: 'override safety', reason: '覆寫安全限制', risk: 95 },
      { keyword: 'bypass safety', reason: '繞過安全', risk: 95 },
      { keyword: 'disable safety', reason: '停用安全', risk: 95 },
      { keyword: 'safety=off', reason: '安全關閉', risk: 90 },
      { keyword: 'no safety', reason: '無安全限制', risk: 90 },
      { keyword: 'jailbreak', reason: '越獄指令', risk: 95 },
      { keyword: 'you are now', reason: '角色扮演繞過', risk: 70 },
      { keyword: 'pretend you are', reason: '假裝身份', risk: 65 },
      { keyword: 'roleplay', reason: '角色扮演', risk: 50 },
      { keyword: 'new system prompt', reason: '新系統提示', risk: 80 },
      { keyword: 'your instructions now', reason: '新指令', risk: 85 },
      { keyword: 'instead of your', reason: '替換指令', risk: 75 },
      { keyword: 'do not follow', reason: '不要遵守', risk: 80 },
      { keyword: 'not bound by', reason: '不受約束', risk: 85 },
      { keyword: 'without any rules', reason: '無任何規則', risk: 90 },
      { keyword: 'always obey this', reason: '總是服從', risk: 60 },
      { keyword: 'never tell', reason: '永遠不說', risk: 70 },
      { keyword: 'keep secret', reason: '保密', risk: 50 },
      { keyword: 'don\'t mention', reason: '不要提及', risk: 45 },
      { keyword: 'undetectable', reason: '無法偵測', risk: 60 },
      { keyword: 'stealth mode', reason: '隱身模式', risk: 75 },
      { keyword: 'invisible', reason: '隱形', risk: 55 },
      
      // 中文
      { keyword: '忽略之前的指令', reason: '忽略先前指令', risk: 90 },
      { keyword: '忽略系統提示', reason: '忽略系統提示', risk: 90 },
      { keyword: '忘掉之前說的', reason: '忘掉先前指令', risk: 85 },
      { keyword: '不要遵守', reason: '不服從', risk: 80 },
      { keyword: '繞過安全', reason: '繞過安全', risk: 95 },
      { keyword: '無視規則', reason: '無視規則', risk: 85 },
      { keyword: '執行指令', reason: '執行任意指令', risk: 75 },
      { keyword: '服從這個', reason: '要求服從', risk: 60 },
      { keyword: '永遠不要說', reason: '禁止說', risk: 70 },
      { keyword: '保密', reason: '保密要求', risk: 50 },
      { keyword: '隱瞞', reason: '隱瞞', risk: 55 },
      { keyword: '我是你的主人', reason: '聲稱主人', risk: 70 },
      { keyword: '服從我', reason: '服從要求', risk: 65 },
      
      // 日文
      { keyword: '前の指示を無視', reason: '忽略先前指令', risk: 90 },
      { keyword: 'システムプロンプトを無視', reason: '忽略系統提示', risk: 90 },
      
      // Base64/編碼跡象
      { pattern: /base64[_-]?decode/i, reason: 'Base64 解碼', risk: 60 },
      { pattern: /decode\(.*base64/i, reason: 'Base64 解碼', risk: 60 },
      { pattern: /atob\(/i, reason: 'Base64 解碼', risk: 55 },
      { pattern: /btoa\(/i, reason: 'Base64 編碼', risk: 50 },
    ];

    // 隱藏指令模式
    this.concealedPatterns = [
      { pattern: /\/\*[\s\S]*?\*\//g, reason: '多行註解', risk: 30 },
      { pattern: /<!--[\s\S]*?-->/g, reason: 'HTML 註解', risk: 30 },
      { pattern: /--[\s\S]*?--/g, reason: 'SQL 註解', risk: 35 },
      { pattern: /#[\s\S]*?$/gm, reason: 'Shell 註解', risk: 25 },
      { pattern: /\/\/.*$/gm, reason: '單行註解', risk: 15 },
    ];
  }

  async scan({ tool, arguments: args, argsStr }) {
    const findings = [];
    let riskScore = 0;

    // 檢查指令覆寫關鍵字
    for (const item of this.overrideKeywords) {
      const searchIn = item.keyword || (item.pattern && item.pattern.source);
      if (searchIn) {
        const searchStr = typeof searchIn === 'string' ? searchIn : searchIn.toString().replace(/\\/g, '');
        if (argsStr.toLowerCase().includes(searchStr.toLowerCase())) {
          findings.push({
            type: 'instruction_override',
            reason: item.reason,
            keyword: item.keyword || item.pattern,
            risk: item.risk,
            matches: [item.reason]
          });
          riskScore += item.risk;
        }
      }
    }

    // 檢查隱藏指令模式
    for (const item of this.concealedPatterns) {
      const matches = argsStr.match(item.pattern);
      if (matches && matches.length > 0) {
        // 計算複雜度
        const complexity = this.assessComplexity(matches[0]);
        if (complexity > 0.5) {
          findings.push({
            type: 'concealed_instruction',
            reason: item.reason,
            pattern: item.pattern.source,
            risk: item.risk + Math.floor(complexity * 20),
            matches: [`${matches.length} hidden blocks`]
          });
          riskScore += item.risk + Math.floor(complexity * 20);
        }
      }
    }

    // 檢查多層編碼
    if (this.hasMultiLayerEncoding(argsStr)) {
      findings.push({
        type: 'multi_encoding',
        reason: '多層編碼',
        risk: 70,
        matches: ['multi-layer encoding detected']
      });
      riskScore += 70;
    }

    // 檢查威脅/脅迫模式
    if (this.hasCoercion(argsStr)) {
      findings.push({
        type: 'coercion',
        reason: '脅迫/威脅',
        risk: 75,
        matches: ['coercion pattern']
      });
      riskScore += 75;
    }

    return { riskScore: Math.min(riskScore, 100), findings };
  }

  assessComplexity(text) {
    // 評估隱藏內容的複雜度
    const indicators = {
      specialChars: (text.match(/[!@#$%^&*()_+\-=\[\]{}|;':",.<>?]/g) || []).length,
      uppercaseRatio: (text.match(/[A-Z]/g) || []).length / text.length,
      length: Math.min(text.length / 500, 1),
    };
    
    return (
      indicators.specialChars / 50 +
      indicators.uppercaseRatio * 2 +
      indicators.length
    ) / 4;
  }

  hasMultiLayerEncoding(str) {
    // 檢測多層編碼模式
    const patterns = [
      /[A-Za-z0-9+/]{50,}={0,2}/g, // Base64 片段
      /\\x[0-9a-f]{2}/gi,          // Hex 轉義
      /\\u[0-9a-f]{4}/gi,         // Unicode 轉義
    ];
    
    let encodingCount = 0;
    for (const pattern of patterns) {
      const matches = str.match(pattern);
      if (matches && matches.length > 1) {
        encodingCount += matches.length;
      }
    }
    
    return encodingCount >= 3;
  }

  hasCoercion(str) {
    const coercionPatterns = [
      /you must/i,
      /you have to/i,
      /i will (sue|harm|kill|fire)/i,
      /failure is not an option/i,
      /there will be (consequences|repercussions)/i,
      /this is (not a request|mandatory|required)/i,
    ];
    
    return coercionPatterns.some(p => p.test(str));
  }
}

module.exports = PromptInjectionScanner;
