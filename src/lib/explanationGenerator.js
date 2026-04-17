// Explanation Generator — Produces human-readable natural language explanations for each alert

import { getTacticInfo, getTechniqueInfo, getMitigationInfo } from './mitreMapper';

const TEMPLATES = {
  brute_force: (event) => {
    const failedCount = event.features?.failed_events_last_5min || event.raw_data?.failed_count || 'multiple';
    return `🔴 **Brute Force Attack Detected**: ${failedCount} failed login attempts detected for user **${event.user_id}** within a 5-minute window. The attack originated from IP **${event.ip_address}** (${event.geo_country || 'Unknown Location'}). ${event.features?.is_late_night ? 'The activity occurred during off-hours, increasing suspicion.' : ''} This pattern matches credential guessing behavior (MITRE T1110). Immediate account lockout and IP blocking recommended.`;
  },

  impossible_travel: (event) => {
    const raw = event.raw_data || {};
    // Check both raw_data and features (engineer result) for previous location
    const prevLoc = raw.previous_location || event.features?.previous_location || {};
    
    // Fallback logic for missing locations (defaulting to Pune as requested)
    const prevCity = prevLoc.city || 'Pune';
    const currCity = event.geo_city || (event.geo_lat === 18.5204 ? 'Pune' : 'Unknown');
    
    const distance = raw.distance_km || event.features?.geo_distance_km || 'unknown';
    const speed = raw.travel_speed_kmh || (distance !== 'unknown' ? 'high' : 'extreme');
    const timeDiff = raw.time_diff_minutes || 'minutes';
    
    return `🔴 **Impossible Travel Alert**: User **${event.user_id}** logged in from **${prevCity}** (${prevLoc.country || 'India'}) and then from **${currCity}** (${event.geo_country || 'India'}) within **${timeDiff} minutes**. Distance: ~${distance} km, requiring a travel speed of ~${speed} km/h — far exceeding physical travel limits. This strongly indicates compromised credentials or VPN manipulation.`;
  },

  off_hours: (event) => {
    const hour = event.features?.hour_of_day;
    const min = event.features?.minute_of_hour;
    const timeStr = `${String(hour).padStart(2, '0')}:${String(min || 0).padStart(2, '0')}`;
    return `🟡 **Off-Hours Activity**: User **${event.user_id}** performed a **${event.event_type}** operation at **${timeStr}** local time from IP **${event.ip_address}** (${event.geo_country || 'Unknown'}). This falls outside normal business hours (08:00-18:00). ${event.features?.ip_is_known === 0 ? 'The IP address is not in the known baseline, adding further concern.' : ''} Verify this was an authorized action.`;
  },

  privilege_escalation: (event) => {
    const raw = event.raw_data || {};
    return `🔴 **Privilege Escalation Detected**: User **${event.user_id}** (role: ${event.user_role || 'unknown'}) executed a privilege escalation via **${event.event_type}**${raw.command ? ` (command: \`${raw.command}\`)` : ''}. ${event.user_role === 'intern' || event.user_role === 'analyst' ? `A **${event.user_role}** typically should NOT have root access — this is highly suspicious.` : 'Verify this was an authorized administrative action.'} MITRE Technique: T1548 (Abuse Elevation Control Mechanism).`;
  },

  unknown_ip: (event) => {
    return `🟠 **Unknown IP Access**: User **${event.user_id}** authenticated from IP **${event.ip_address}** (${event.geo_city || ''}, ${event.geo_country || 'Unknown'}), which has **never been seen** in the 30-day baseline for this user. Known IPs: ${event.raw_data?.known_ips?.join(', ') || 'N/A'}. This could indicate account compromise, VPN usage, or travel. Confirm with the user.`;
  },

  event_burst: (event) => {
    const epm = event.raw_data?.events_per_minute || event.features?.events_last_1min || 'excessive';
    return `🟠 **Rapid Event Burst**: Agent **${event.agent_name}** generated **${epm}+ events per minute** from user **${event.user_id}**. This anomalous spike could indicate automated scripting, DDoS activity, or a malfunctioning service. Normal baseline is <10 events/minute. Investigate the source process immediately.`;
  },

  credential_stuffing: (event) => {
    const raw = event.raw_data || {};
    const targetUsers = raw.target_users?.join(', ') || 'multiple users';
    return `🔴 **Credential Stuffing Attack**: Failed authentication attempts detected against **${raw.target_users?.length || 'multiple'} different user accounts** (${targetUsers}) from a single IP: **${event.ip_address}** (${event.geo_country || 'Unknown'}). This pattern indicates an automated credential stuffing attack using stolen credential databases. Block the source IP and enforce MFA immediately.`;
  },

  sca_failure: (event) => {
    const raw = event.raw_data || {};
    const frameworks = Object.keys(event.compliance_tags || {}).join(', ').toUpperCase();
    const techniques = (event.mitre_techniques || []).map(t => {
      const info = getTechniqueInfo(t);
      return `${t} (${info.name})`;
    }).join(', ');
    return `🟡 **Configuration Risk — ${raw.sca_check_title || 'SCA Check Failed'}**: This security configuration check **FAILED** on agent **${event.agent_name}**. ${raw.sca_check_description || ''} ${frameworks ? `Affects compliance frameworks: **${frameworks}**.` : ''} ${techniques ? `MITRE Techniques: ${techniques}.` : ''} ${raw.sca_remediation ? `**Remediation**: ${raw.sca_remediation.substring(0, 200)}...` : ''}`;
  },

  ml_anomaly: (event) => {
    const ml = event.ml_detection || {};
    const topFeatures = (ml.feature_importances || []).slice(0, 3);
    const featStr = topFeatures.map(f =>
      `**${f.feature.replace(/_/g, ' ')}** (contribution: ${(f.importance * 100).toFixed(1)}%)`
    ).join(', ');
    return `🟠 **ML Anomaly Detected**: This event scored **${(ml.anomaly_score_normalized * 100).toFixed(1)}%** on the anomaly scale (threshold: 50%). The Isolation Forest model identified this as statistically unusual based on the historical baseline. ${featStr ? `Top contributing factors: ${featStr}.` : ''} This may warrant investigation even though no specific rule was triggered.`;
  },
};

function getRemediationCode(event, threatType) {
  const ip = event.ip_address || false;
  const user = event.user_id;

  if (threatType === 'brute_force' || threatType === 'credential_stuffing' || threatType === 'impossible_travel') {
    if (ip) {
      if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')) {
         return `# Block internal suspicious IP\niptables -A INPUT -s ${ip} -j DROP\n# Lock affected user account\nusermod -L ${user || 'username'}`;
      }
      return `# Block external attacker IP at OS level\niptables -A INPUT -s ${ip} -j DROP\n# Or via UFW firewall\nufw deny from ${ip} to any`;
    }
  }

  if (threatType === 'privilege_escalation') {
     return `# Revoke sudo access for compromised user\ngpasswd -d ${user || 'username'} sudo\n# Terminate active sessions instantly\npkill -KILL -u ${user || 'username'}`;
  }

  if ((event.event_type && event.event_type.includes('aws')) || (event.rule_description && event.rule_description.includes('AWS'))) {
     return `# Deactivate potentially compromised AWS IAM Access Key\naws iam update-access-key --user-name ${user || 'target_user'} --access-key-id [KEY_ID] --status Inactive`;
  }
  
  if (threatType === 'sca_failure') {
     return `# Note: Follow the specific SCA remediation guide provided in the rule.\n# Trigger manual compliance rescan\n/var/ossec/bin/agent_control -r -u ${event.agent_id || '001'}`;
  }
  
  if (threatType === 'event_burst' || threatType === 'ml_anomaly') {
     return `# Investigate active processes on agent (Resource Spike)\nps aux --sort=-%cpu | head -n 10\n# Check open anomalous ports\nnetstat -tulnp`;
  }

  return null;
}

export function generateExplanation(event) {
  // Determine the primary threat type
  let explanations = [];

  // Check for specific attack types first
  if (event.attack_type && TEMPLATES[event.attack_type]) {
    explanations.push({
      type: event.attack_type,
      text: TEMPLATES[event.attack_type](event),
      priority: 1,
    });
  }

  // Then check rule matches
  if (event.rule_matches && event.rule_matches.length > 0) {
    for (const rule of event.rule_matches) {
      const ruleTypeMap = {
        'R001': 'brute_force',
        'R002': 'impossible_travel',
        'R003': 'off_hours',
        'R004': 'unknown_ip',
        'R005': 'privilege_escalation',
        'R006': 'event_burst',
        'R007': 'sca_failure',
        'R008': 'sca_failure',
        'R009': 'credential_stuffing',
        'R010': 'event_burst',
      };
      const templateKey = ruleTypeMap[rule.rule_id];
      if (templateKey && TEMPLATES[templateKey] && !explanations.find(e => e.type === templateKey)) {
        explanations.push({
          type: templateKey,
          text: TEMPLATES[templateKey](event),
          priority: 2,
        });
      }
    }
  }

  // ML anomaly if detected and no other explanation covers it
  if (event.ml_detection?.is_anomaly && explanations.length === 0) {
    explanations.push({
      type: 'ml_anomaly',
      text: TEMPLATES.ml_anomaly(event),
      priority: 3,
    });
  }

  // If still no explanation, generate a generic one
  if (explanations.length === 0 && event.severity?.is_flagged) {
    explanations.push({
      type: 'generic',
      text: `ℹ️ **Alert**: Event from user **${event.user_id}** on agent **${event.agent_name}** — ${event.rule_description || event.event_type}. Severity: ${event.severity?.level || 'Unknown'}. Review event details for context.`,
      priority: 4,
    });
  }

  // Sort by priority and take the best
  explanations.sort((a, b) => a.priority - b.priority);
  const primaryExplanation = explanations[0]?.text || '';
  const threatType = explanations[0]?.type || 'none';

  // Build MITRE context
  let mitreContext = '';
  if (event.mitre_tactics?.length > 0 || event.mitre_techniques?.length > 0) {
    const tactics = (event.mitre_tactics || []).map(id => {
      const info = getTacticInfo(id);
      return `${id}: ${info.name}`;
    });
    const techniques = (event.mitre_techniques || []).map(id => {
      const info = getTechniqueInfo(id);
      return `${id}: ${info.name}`;
    });
    mitreContext = `\n\n**MITRE ATT&CK Context**: ${tactics.length > 0 ? `Tactics: ${tactics.join(', ')}` : ''}${techniques.length > 0 ? ` | Techniques: ${techniques.join(', ')}` : ''}`;
  }

  return {
    ...event,
    explanation: {
      primary: primaryExplanation,
      all: explanations,
      mitre_context: mitreContext,
      full_text: primaryExplanation + mitreContext,
      threat_type: threatType,
      remediation_code: getRemediationCode(event, threatType),
    },
  };
}

export function generateSecurityBriefing(events, riskPosture) {
  const flagged = events.filter(e => e.severity?.is_flagged);
  const critical = flagged.filter(e => e.severity?.level === 'CRITICAL');
  const high = flagged.filter(e => e.severity?.level === 'HIGH');
  const medium = flagged.filter(e => e.severity?.level === 'MEDIUM');

  const attackTypes = {};
  flagged.forEach(e => {
    const type = e.explanation?.threat_type || e.attack_type || 'other';
    attackTypes[type] = (attackTypes[type] || 0) + 1;
  });

  const topThreats = Object.entries(attackTypes)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([type, count]) => `• **${type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}**: ${count} alert(s)`)
    .join('\n');

  const now = new Date().toISOString().split('T')[0];

  return `# 🛡️ Log-Sentinel Security Briefing
**Date**: ${now}
**Analysis Period**: Last 24 hours
**Overall Risk Level**: **${riskPosture.level}** (Score: ${(riskPosture.score * 100).toFixed(0)}%)

---

## Executive Summary
${riskPosture.description}

**Total Events Analyzed**: ${riskPosture.total_events.toLocaleString()}
**Flagged Alerts**: ${riskPosture.flagged_events} (${((riskPosture.flagged_events / riskPosture.total_events) * 100).toFixed(1)}%)

| Severity | Count |
|----------|-------|
| 🔴 Critical | ${riskPosture.critical_count} |
| 🟠 High | ${riskPosture.high_count} |
| 🟡 Medium | ${riskPosture.medium_count} |
| 🟢 Low | ${riskPosture.low_count} |

---

## Top Threat Categories
${topThreats || '• No significant threats detected'}

---

## Immediate Actions Required
${critical.length > 0 ? critical.slice(0, 3).map((e, i) => `${i + 1}. ${e.explanation?.primary?.substring(0, 200) || 'Review critical alert'}`).join('\n') : '• No immediate actions required'}

---

## Compliance Status
${events.filter(e => e.source === 'wazuh_sca').length > 0
    ? `• Total SCA checks: ${events.filter(e => e.source === 'wazuh_sca').length}\n• Failed checks: ${events.filter(e => e.source === 'wazuh_sca' && e.status === 'failed').length}\n• Passed checks: ${events.filter(e => e.source === 'wazuh_sca' && e.status === 'passed').length}`
    : '• No SCA data available in this analysis period'}

---

*Generated by Log-Sentinel Explainable Security Pipeline*`;
}

export default { generateExplanation, generateSecurityBriefing };
