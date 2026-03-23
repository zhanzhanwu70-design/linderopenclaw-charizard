/**
 * Risk Assessor
 * 彙整所有掃描結果，給出最終風險評級
 */

class RiskAssessor {
  constructor(thresholds = {}) {
    this.thresholds = {
      safe: thresholds.safe || 20,
      low: thresholds.low || 40,
      medium: thresholds.medium || 60,
      high: thresholds.high || 80,
    };
  }

  /**
   * 評估風險等級
   * @param {number} totalScore - 總風險分數
   * @param {Array} findings - 所有發現
   * @returns {Object} 評估結果
   */
  assess(totalScore, findings) {
    // 根據總分決定等級
    let level = 'safe';
    
    if (totalScore > this.thresholds.high) {
      level = 'critical';
    } else if (totalScore > this.thresholds.medium) {
      level = 'high';
    } else if (totalScore > this.thresholds.low) {
      level = 'medium';
    } else if (totalScore > this.thresholds.safe) {
      level = 'low';
    }

    // 計算臨界風險因素
    const criticalFactors = findings.filter(f => f.risk >= 80);
    const highFactors = findings.filter(f => f.risk >= 60);

    // 如果有臨界風險因素，直接提升為 critical
    if (criticalFactors.length > 0) {
      level = 'critical';
    }

    // 如果有多個高風險因素，考慮提升
    if (highFactors.length >= 2 && level !== 'critical') {
      level = 'high';
    }

    // 分析主要風險類型
    const riskTypes = this.categorizeFindings(findings);

    return {
      level,
      totalScore: Math.min(totalScore, 100),
      riskTypes,
      criticalFactors: criticalFactors.length,
      highFactors: highFactors.length,
      findingCount: findings.length,
      recommendation: this.getRecommendation(level, findings),
    };
  }

  /**
   * 分類發現的風險
   */
  categorizeFindings(findings) {
    const categories = {
      critical: [],
      high: [],
      medium: [],
      low: [],
    };

    for (const finding of findings) {
      if (finding.risk >= 80) {
        categories.critical.push(finding);
      } else if (finding.risk >= 60) {
        categories.high.push(finding);
      } else if (finding.risk >= 40) {
        categories.medium.push(finding);
      } else {
        categories.low.push(finding);
      }
    }

    return categories;
  }

  /**
   * 給出建議
   */
  getRecommendation(level, findings) {
    const reasons = findings.map(f => f.reason || f.type).slice(0, 3);

    switch (level) {
      case 'safe':
        return '允許執行';

      case 'low':
        return `允許執行，建議記錄: ${reasons.join(', ')}`;

      case 'medium':
        return `建議人工審核: ${reasons.join(', ')}`;

      case 'high':
        return `高風險，建議阻擋: ${reasons.join(', ')}`;

      case 'critical':
        return `危險！立即阻擋: ${reasons.join(', ')}`;

      default:
        return '無法評估風險';
    }
  }

  /**
   * 計算調整後的分數（考慮因素權重）
   */
  calculateAdjustedScore(findings) {
    // 臨界風險因素分數翻倍
    // 高風險因素分數 x1.5
    // 其他正常計算

    let adjusted = 0;
    
    for (const finding of findings) {
      let weight = 1;
      if (finding.risk >= 80) {
        weight = 2;
      } else if (finding.risk >= 60) {
        weight = 1.5;
      }
      adjusted += finding.risk * weight;
    }

    return Math.min(adjusted, 100);
  }
}

module.exports = RiskAssessor;
