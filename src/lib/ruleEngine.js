// Rule Engine — Deterministic signature-based threat detection

const RULES = [
  {
    id: 'R001',
    name: 'Brute Force Attempt',
    description: 'Multiple failed login attempts within a short time window',
    severity: 'CRITICAL',
    severityScore: 0.95,
    check: (event, context) => {
      const f = event.features;
      if (!f) return false;
      return f.failed_events_last_5min >= 5 && event.event_type === 'login';
    },
  },
  {
    id: 'R002',
    name: 'Impossible Travel',
    description: 'Login from geographically distant locations within an impossible timeframe',
    severity: 'CRITICAL',
    severityScore: 0.92,
    check: (event) => {
      const f = event.features;
      if (!f) return false;
      return f.impossible_travel_flag === 1;
    },
  },
  {
    id: 'R003',
    name: 'Off-Hours Login',
    description: 'Successful authentication during abnormal hours (00:00 - 05:00)',
    severity: 'MEDIUM',
    severityScore: 0.55,
    check: (event) => {
      const f = event.features;
      if (!f) return false;
      return f.is_late_night === 1 && event.event_type === 'login' && event.status === 'success';
    },
  },
  {
    id: 'R004',
    name: 'Unknown IP Access',
    description: 'Login from an IP address not seen in the historical baseline',
    severity: 'MEDIUM',
    severityScore: 0.60,
    check: (event) => {
      const f = event.features;
      if (!f) return false;
      return f.ip_is_known === 0 && f.ip_is_private === 0 && event.event_type === 'login';
    },
  },
  {
    id: 'R005',
    name: 'Privilege Escalation',
    description: 'Unauthorized or anomalous privilege elevation detected',
    severity: 'HIGH',
    severityScore: 0.85,
    check: (event) => {
      const f = event.features;
      if (!f) return false;
      return f.privilege_level_change === 1;
    },
  },
  {
    id: 'R006',
    name: 'Rapid Event Burst',
    description: 'Abnormal spike in event frequency from a single source',
    severity: 'HIGH',
    severityScore: 0.75,
    check: (event) => {
      const f = event.features;
      if (!f) return false;
      if (event.source === 'wazuh_sca') return false; // SCA scans naturally produce bursts
      return f.events_last_1min > 30;
    },
  },
  {
    id: 'R007',
    name: 'SCA Critical Failure',
    description: 'Security Configuration Assessment check failed with high severity and MITRE mapping',
    severity: 'MEDIUM',
    severityScore: 0.50,
    check: (event) => {
      return event.source === 'wazuh_sca' &&
        event.status === 'failed' &&
        event.severity_level >= 7 &&
        (event.mitre_techniques || []).length > 0;
    },
  },
  {
    id: 'R008',
    name: 'Compliance Violation Cluster',
    description: 'Multiple SCA compliance failures detected in a single scan',
    severity: 'HIGH',
    severityScore: 0.70,
    check: (event, context) => {
      if (event.source !== 'wazuh_sca' || event.status !== 'failed') return false;
      const f = event.features;
      return f && f.compliance_framework_count >= 5;
    },
  },
  {
    id: 'R009',
    name: 'Credential Stuffing',
    description: 'Failed authentication attempts against multiple users from the same IP',
    severity: 'CRITICAL',
    severityScore: 0.90,
    check: (event) => {
      return event.attack_type === 'credential_stuffing';
    },
  },
  {
    id: 'R010',
    name: 'Abnormal Access Frequency',
    description: 'Event count significantly exceeds the user baseline',
    severity: 'MEDIUM',
    severityScore: 0.50,
    check: (event) => {
      const f = event.features;
      if (!f) return false;
      return f.events_last_1hour > 50 && f.event_type_rarity > 0.7;
    },
  },
];

export function runRuleEngine(events) {
  return events.map(event => {
    const matchedRules = [];
    for (const rule of RULES) {
      try {
        if (rule.check(event, { events })) {
          matchedRules.push({
            rule_id: rule.id,
            rule_name: rule.name,
            description: rule.description,
            severity: rule.severity,
            severityScore: rule.severityScore,
          });
        }
      } catch (e) {
        // Skip rule on error
      }
    }
    return {
      ...event,
      rule_matches: matchedRules,
      rule_max_severity: matchedRules.length > 0
        ? Math.max(...matchedRules.map(r => r.severityScore))
        : 0,
      rule_detected: matchedRules.length > 0,
    };
  });
}

export { RULES };
export default { runRuleEngine, RULES };
