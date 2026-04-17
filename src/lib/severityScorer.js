// Severity Scorer — Composite scoring algorithm combining rule-based and ML detections

export function computeSeverityScores(events) {
  return events.map(event => {
    const ruleScore = event.rule_max_severity || 0;
    const mlScore = event.ml_detection?.anomaly_score_normalized || 0;

    // Compliance impact score
    const complianceCount = Object.keys(event.compliance_tags || {}).length;
    const complianceImpact = Math.min(1, complianceCount / 6);

    // MITRE technique coverage
    const techniqueCount = (event.mitre_techniques || []).length;
    const tacticCount = (event.mitre_tactics || []).length;
    const mitreCoverage = Math.min(1, (techniqueCount + tacticCount) / 6);

    // Temporal risk factor
    const f = event.features || {};
    const temporalRisk = (
      (f.is_late_night || 0) * 0.4 +
      (f.is_weekend || 0) * 0.2 +
      (1 - (f.is_business_hours || 0)) * 0.2 +
      (f.ip_country_changed || 0) * 0.2
    );

    // Composite severity score
    const severityScore = (
      0.35 * ruleScore +
      0.25 * mlScore +
      0.15 * complianceImpact +
      0.15 * mitreCoverage +
      0.10 * temporalRisk
    );

    // Clamp between 0 and 1
    const finalScore = Math.min(1, Math.max(0, severityScore));

    // Determine risk level
    let riskLevel, riskColor;
    if (finalScore >= 0.85) {
      riskLevel = 'CRITICAL';
      riskColor = '#ff1744';
    } else if (finalScore >= 0.6) {
      riskLevel = 'HIGH';
      riskColor = '#ff6d00';
    } else if (finalScore >= 0.3) {
      riskLevel = 'MEDIUM';
      riskColor = '#ffc400';
    } else {
      riskLevel = 'LOW';
      riskColor = '#00e676';
    }

    // Determine if this alert should be flagged
    const is_flagged = finalScore >= 0.25 || event.rule_detected || event.ml_detection?.is_anomaly;

    return {
      ...event,
      severity: {
        score: Math.round(finalScore * 1000) / 1000,
        level: riskLevel,
        color: riskColor,
        components: {
          rule_score: Math.round(ruleScore * 1000) / 1000,
          ml_score: Math.round(mlScore * 1000) / 1000,
          compliance_impact: Math.round(complianceImpact * 1000) / 1000,
          mitre_coverage: Math.round(mitreCoverage * 1000) / 1000,
          temporal_risk: Math.round(temporalRisk * 1000) / 1000,
        },
        is_flagged,
      },
    };
  });
}

export function rankBySeverity(events) {
  return [...events]
    .filter(e => e.severity?.is_flagged)
    .sort((a, b) => (b.severity?.score || 0) - (a.severity?.score || 0));
}

export function getSeverityDistribution(events) {
  const dist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  events.forEach(e => {
    if (e.severity?.is_flagged) {
      dist[e.severity.level] = (dist[e.severity.level] || 0) + 1;
    }
  });
  return dist;
}

export function getOverallRiskPosture(events) {
  const flagged = events.filter(e => e.severity?.is_flagged);
  if (flagged.length === 0) return { score: 0, level: 'LOW', description: 'No threats detected' };

  const avgScore = flagged.reduce((sum, e) => sum + (e.severity?.score || 0), 0) / flagged.length;
  const maxScore = Math.max(...flagged.map(e => e.severity?.score || 0));
  const criticalCount = flagged.filter(e => e.severity?.level === 'CRITICAL').length;

  // Weighted overall score
  const overallScore = Math.min(1, avgScore * 0.4 + maxScore * 0.4 + Math.min(1, criticalCount / 3) * 0.2);

  let level, description;
  if (overallScore >= 0.7) {
    level = 'CRITICAL';
    description = `Critical threats detected. ${criticalCount} critical alert(s) require immediate attention.`;
  } else if (overallScore >= 0.5) {
    level = 'HIGH';
    description = `Multiple high-severity threats detected. Security investigation recommended.`;
  } else if (overallScore >= 0.3) {
    level = 'MEDIUM';
    description = `Moderate risk levels detected. Review flagged alerts and compliance gaps.`;
  } else {
    level = 'LOW';
    description = `Low risk posture. Minor alerts may need periodic review.`;
  }

  return {
    score: Math.round(overallScore * 100) / 100,
    level,
    description,
    total_events: events.length,
    flagged_events: flagged.length,
    critical_count: criticalCount,
    high_count: flagged.filter(e => e.severity?.level === 'HIGH').length,
    medium_count: flagged.filter(e => e.severity?.level === 'MEDIUM').length,
    low_count: flagged.filter(e => e.severity?.level === 'LOW').length,
  };
}

export default { computeSeverityScores, rankBySeverity, getSeverityDistribution, getOverallRiskPosture };
