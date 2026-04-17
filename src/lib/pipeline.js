// Pipeline — Full end-to-end security analysis orchestrator

import { generateSimulatedLogs } from './logSimulator';
import { fetchWazuhAlerts, normalizeWazuhAlerts } from './wazuhClient';
import { loadCSVLogs } from './csvLogParser';
import { engineerFeatures } from './featureEngineer';
import { runRuleEngine } from './ruleEngine';
import { runMLDetection } from './mlDetector';
import { computeSeverityScores, rankBySeverity, getSeverityDistribution, getOverallRiskPosture } from './severityScorer';
import { generateExplanation, generateSecurityBriefing } from './explanationGenerator';
import { enrichWithMitre, getMitreHeatmapData } from './mitreMapper';

export async function runPipeline(options = {}) {
  const startTime = Date.now();

  // Step 1: Data Ingestion
  let allEvents = [];
  let csvEventCount = 0;
  let wazuhEventCount = 0;
  let simulatedCount = 0;

  // PRIMARY SOURCE: Client Injected CSV or Local CSV
  console.log('[Pipeline] Loading CSV log data...');
  let csvEvents = [];
  if (options.csvData && options.csvData.length > 0) {
    console.log(`[Pipeline] Core received ${options.csvData.length} records via Drag-and-Drop upload`);
    csvEvents = options.csvData;
  } else {
    csvEvents = loadCSVLogs();
  }
  
  csvEventCount = csvEvents.length;
  if (csvEventCount > 0) {
    allEvents.push(...csvEvents);
    console.log(`[Pipeline] Loaded ${csvEventCount} events from CSV source`);
  } else {
    // Fallback to simulated logs if CSV not available
    console.log('[Pipeline] CSV not found, falling back to simulated logs');
    const simulatedEvents = generateSimulatedLogs({
      normalCount: options.normalCount || 250,
      bruteForceCount: options.bruteForceCount || 2,
      impossibleTravelCount: options.impossibleTravelCount || 2,
      offHoursCount: options.offHoursCount || 3,
      privEscCount: options.privEscCount || 2,
      unknownIPCount: options.unknownIPCount || 3,
      eventBurstCount: options.eventBurstCount || 1,
      credStuffingCount: options.credStuffingCount || 1,
      daysBack: options.daysBack || 1,
    });
    simulatedCount = simulatedEvents.length;
    allEvents.push(...simulatedEvents);
  }

  // SECONDARY SOURCE: Live Wazuh API (supplemental)
  if (options.includeWazuh !== false) {
    try {
      let wazuhData = options.wazuhData || null;
      if (!wazuhData) {
        console.log('[Pipeline] Fetching live Wazuh alerts from Elasticsearch...');
        wazuhData = await fetchWazuhAlerts(500);
      }
      if (wazuhData) {
        const wazuhEvents = normalizeWazuhAlerts(wazuhData);
        wazuhEventCount = wazuhEvents.length;
        allEvents.push(...wazuhEvents);
        console.log(`[Pipeline] Ingested ${wazuhEventCount} live Wazuh alerts`);
      }
    } catch (err) {
      console.error('[Pipeline] Wazuh fetch error:', err.message);
    }
  }

  // Sort all events by timestamp
  allEvents.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  // Step 2: Feature Engineering
  console.log(`[Pipeline] Engineering features for ${allEvents.length} events...`);
  const featuredEvents = engineerFeatures(allEvents);

  // Step 3: Rule-Based Detection
  console.log('[Pipeline] Running rule-based detection...');
  const ruleDetectedEvents = runRuleEngine(featuredEvents);

  // Step 4: ML Anomaly Detection (Isolation Forest)
  console.log(`[Pipeline] Running ML anomaly detection (threshold: ${options.anomalyThreshold || 0.08})...`);
  const mlDetectedEvents = runMLDetection(ruleDetectedEvents, options);

  // Step 5: Severity Scoring
  console.log('[Pipeline] Computing severity scores...');
  const scoredEvents = computeSeverityScores(mlDetectedEvents);

  // Step 6: MITRE ATT&CK Enrichment
  const enrichedEvents = scoredEvents.map(evt => enrichWithMitre(evt));

  // Step 7: Generate Explanations
  const explainedEvents = enrichedEvents.map(evt => generateExplanation(evt));

  // Step 8: Rank, aggregate, and perform Root Cause Analysis (RCA)
  let flaggedAlerts = rankBySeverity(explainedEvents);
  
  // RCA Extraction: Find preceding correlated events for Critical/High alerts
  flaggedAlerts = flaggedAlerts.map(alert => {
    if (alert.severity?.level === 'CRITICAL' || alert.severity?.level === 'HIGH') {
      const alertTime = new Date(alert.timestamp).getTime();
      const oneHourAgo = alertTime - 60 * 60 * 1000;
      
      const relatedEvents = allEvents.filter(e => {
        const t = new Date(e.timestamp).getTime();
        // Must be before the alert and within 1 hour
        if (t >= alertTime || t < oneHourAgo) return false;
        
        // Match by IP or User
        const matchIp = alert.ip_address && e.ip_address === alert.ip_address;
        const matchUser = alert.user_id && e.user_id === alert.user_id;
        
        return matchIp || matchUser;
      });

      // Take the 5 most recent related events leading up to this alert
      const attackChain = relatedEvents
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 5)
        .reverse()  // Chronological order leading up to alert
        .map(e => ({
          timestamp: e.timestamp,
          event_type: e.event_type || 'Unknown Event',
          agent: e.agent_name || 'System',
          status: e.status,
          rule: e.rule_description || 'Raw Audit Log'
        }));

      if (attackChain.length > 0) {
        return { ...alert, rca_chain: attackChain };
      }
    }
    return alert;
  });

  const severityDistribution = getSeverityDistribution(explainedEvents);
  const riskPosture = getOverallRiskPosture(explainedEvents);
  const mitreHeatmap = getMitreHeatmapData(explainedEvents);

  // Step 9: Generate briefing
  const securityBriefing = generateSecurityBriefing(explainedEvents, riskPosture);

  // Step 10: Build timeline
  const timeline = explainedEvents
    .filter(e => e.severity?.is_flagged)
    .map(e => ({
      timestamp: e.timestamp,
      event_id: e.event_id,
      user: e.user_id,
      type: e.explanation?.threat_type || e.event_type,
      severity: e.severity?.level,
      score: e.severity?.score,
      summary: e.explanation?.primary?.substring(0, 150) || e.rule_description,
    }))
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  // Attack type summary
  const attackTypeSummary = {};
  flaggedAlerts.forEach(e => {
    const type = e.explanation?.threat_type || 'other';
    if (!attackTypeSummary[type]) {
      attackTypeSummary[type] = { count: 0, max_severity: 0, events: [] };
    }
    attackTypeSummary[type].count++;
    attackTypeSummary[type].max_severity = Math.max(attackTypeSummary[type].max_severity, e.severity?.score || 0);
    if (attackTypeSummary[type].events.length < 3) {
      attackTypeSummary[type].events.push(e.event_id);
    }
  });

  // Compliance summary (for all sources)
  const complianceEvents = explainedEvents.filter(e =>
    e.source === 'wazuh_sca' || e.source === 'csv_wazuh'
  );
  const failedChecks = complianceEvents.filter(e =>
    e.status === 'failed' || e.attack_type === 'oscap_scan' || e.attack_type === 'cis_benchmark'
  );
  const passedChecks = complianceEvents.filter(e => e.status === 'passed');
  const complianceSummary = {
    total_checks: complianceEvents.length,
    passed: passedChecks.length,
    failed: failedChecks.length,
    not_applicable: complianceEvents.filter(e => e.status === 'not applicable').length,
    pass_rate: complianceEvents.length > 0
      ? Math.round((passedChecks.length / complianceEvents.length) * 100)
      : 0,
    failed_checks: failedChecks.slice(0, 50).map(e => ({
      title: e.raw_data?.sca_check_title || e.raw_data?.oscap?.title || e.raw_data?.cis?.rule_title || e.rule_description,
      severity: e.severity_level,
      remediation: e.raw_data?.sca_remediation?.substring(0, 200) || e.raw_data?.oscap?.description?.substring(0, 200) || '',
      compliance: Object.keys(e.compliance_tags || {}),
    })),
  };

  const processingTime = Date.now() - startTime;
  console.log(`[Pipeline] Complete in ${processingTime}ms — ${flaggedAlerts.length} alerts flagged`);

  return {
    metadata: {
      generated_at: new Date().toISOString(),
      processing_time_ms: processingTime,
      pipeline_version: '1.0.0',
      total_events: allEvents.length,
      flagged_alerts: flaggedAlerts.length,
      data_sources: {
        csv_wazuh: csvEventCount,
        wazuh_live: wazuhEventCount,
        simulated: simulatedCount,
      },
      wazuh_live: wazuhEventCount > 0,
      csv_loaded: csvEventCount > 0,
    },
    risk_posture: riskPosture,
    severity_distribution: severityDistribution,
    top_alerts: flaggedAlerts.slice(0, 20).map(sanitizeForJSON),
    all_alerts: flaggedAlerts.map(sanitizeForJSON),
    timeline,
    mitre_heatmap: mitreHeatmap,
    attack_type_summary: attackTypeSummary,
    compliance_summary: complianceSummary,
    security_briefing: securityBriefing,
  };
}

function sanitizeForJSON(event) {
  return {
    event_id: event.event_id,
    timestamp: event.timestamp,
    source: event.source,
    agent_name: event.agent_name,
    user_id: event.user_id,
    user_role: event.user_role,
    ip_address: event.ip_address,
    event_type: event.event_type,
    status: event.status,
    geo_country: event.geo_country,
    geo_city: event.geo_city,
    attack_type: event.attack_type,
    severity: event.severity,
    rule_matches: event.rule_matches,
    mitre_tactics: event.mitre_tactics,
    mitre_techniques: event.mitre_techniques,
    mitre_tactic_details: event.mitre_tactic_details,
    mitre_technique_details: event.mitre_technique_details,
    compliance_tags: event.compliance_tags,
    explanation: event.explanation,
    ml_detection: event.ml_detection ? {
      anomaly_score_normalized: event.ml_detection.anomaly_score_normalized,
      is_anomaly: event.ml_detection.is_anomaly,
      feature_importances: event.ml_detection.feature_importances,
      model_status: event.ml_detection.model_status,
    } : null,
    features: event.features ? {
      hour_of_day: event.features.hour_of_day,
      is_business_hours: event.features.is_business_hours,
      is_late_night: event.features.is_late_night,
      failed_events_last_5min: event.features.failed_events_last_5min,
      events_last_1min: event.features.events_last_1min,
      ip_is_known: event.features.ip_is_known,
      geo_distance_km: event.features.geo_distance_km,
      impossible_travel_flag: event.features.impossible_travel_flag,
    } : null,
    raw_data: event.raw_data ? {
      sca_check_title: event.raw_data.sca_check_title,
      sca_remediation: event.raw_data.sca_remediation?.substring(0, 300),
      sca_policy: event.raw_data.sca_policy,
    } : null,
  };
}

export default { runPipeline };
