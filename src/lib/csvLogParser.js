// CSV Log Parser — Parses Wazuh CSV export into normalized pipeline events
import { readFileSync } from 'fs';
import { join } from 'path';

const CSV_FILENAME = 'On_demand_report_2026-04-16T20_27_10.959Z_a59c37f0-39d2-11f1-b115-490c180146ed.csv';

// Parse CSV handling quoted fields with commas and nested quotes
function parseCSVLine(line) {
  const fields = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && i + 1 < line.length && line[i + 1] === '"') {
        current += '"';
        i++; // skip escaped quote
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      fields.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current.trim());
  return fields;
}

// Parse the Wazuh timestamp format: "Apr 17, 2026 @ 00:11:16.415"
function parseWazuhTimestamp(ts) {
  if (!ts) return new Date().toISOString();
  try {
    const cleaned = ts.replace(' @ ', ' ').replace(/"/g, '');
    const d = new Date(cleaned);
    if (!isNaN(d.getTime())) return d.toISOString();
  } catch (e) { }
  return new Date().toISOString();
}

// Clean array-like string: "[""wazuh"",""rootcheck""]" -> ["wazuh","rootcheck"]
function parseArrayField(val) {
  if (!val) return [];
  try {
    const cleaned = val.replace(/""/g, '"');
    if (cleaned.startsWith('[')) {
      return JSON.parse(cleaned);
    }
  } catch (e) { }
  return val ? [val] : [];
}

// Clean JSON-like string
function parseJSONField(val) {
  if (!val) return {};
  try {
    const cleaned = val.replace(/""/g, '"');
    return JSON.parse(cleaned);
  } catch (e) { }
  return {};
}

// Determine attack type from rule description/groups
function classifyAttackType(ruleDesc, ruleGroups, ruleLevel, decoderName, fullLog) {
  const desc = (ruleDesc || '').toLowerCase();
  const groups = (ruleGroups || '').toLowerCase();
  const log = (fullLog || '').toLowerCase();

  if (desc.includes('rootkit') || desc.includes('trojaned')) return 'rootkit_detection';
  if (desc.includes('brute') || desc.includes('multiple failed') || desc.includes('authentication fail')) return 'brute_force';
  if (desc.includes('virus') || desc.includes('malware') || desc.includes('malicious')) return 'malware_detection';
  if (desc.includes('integrity') || groups.includes('syscheck')) return 'file_integrity';
  if (desc.includes('audit') || groups.includes('audit')) return 'audit_event';
  if (groups.includes('oscap') || desc.includes('oscap') || desc.includes('openscap')) return 'oscap_scan';
  if (groups.includes('vulnerability') || desc.includes('vulnerability')) return 'vulnerability';
  if (groups.includes('aws') || desc.includes('guardduty') || desc.includes('aws')) return 'aws_guardduty';
  if (groups.includes('office365') || desc.includes('office365')) return 'office365';
  if (desc.includes('login') || desc.includes('logon') || desc.includes('ssh')) return 'auth_event';
  if (groups.includes('cis') || desc.includes('cis benchmark')) return 'cis_benchmark';
  if (desc.includes('port') || desc.includes('scan')) return 'port_scan';
  if (desc.includes('privilege') || desc.includes('sudo') || desc.includes('escalat')) return 'privilege_escalation';
  if (desc.includes('firewall') || desc.includes('iptables')) return 'firewall_event';
  if (groups.includes('web') || desc.includes('web') || desc.includes('sql')) return 'web_attack';
  if (groups.includes('rootcheck')) return 'rootcheck';
  return 'generic_alert';
}

// Map rule level to severity
function levelToSeverity(level) {
  if (level >= 12) return 'CRITICAL';
  if (level >= 8) return 'HIGH';
  if (level >= 5) return 'MEDIUM';
  return 'LOW';
}

export function loadCSVLogs() {
  try {
    // Try multiple paths
    const paths = [
      join(process.cwd(), CSV_FILENAME),
      join(process.cwd(), 'data', CSV_FILENAME),
    ];

    let csvContent = null;
    for (const p of paths) {
      try {
        csvContent = readFileSync(p, 'utf-8');
        console.log(`[CSV Parser] Loaded CSV from: ${p} (${(csvContent.length / 1024 / 1024).toFixed(1)}MB)`);
        break;
      } catch (e) {
        // Try next path
      }
    }

    if (!csvContent) {
      console.error('[CSV Parser] CSV file not found');
      return [];
    }

    const lines = csvContent.split('\n').filter(l => l.trim());
    if (lines.length < 2) return [];

    // Parse header
    const headers = parseCSVLine(lines[0]);
    const headerMap = {};
    headers.forEach((h, i) => { headerMap[h.replace(/_source\./g, '')] = i; });

    console.log(`[CSV Parser] Parsing ${lines.length - 1} rows with ${headers.length} columns`);

    // Build column index lookup
    const col = (name) => {
      // Try both with and without _source. prefix
      const idx = headerMap[name] ?? headerMap[`_source.${name}`];
      return idx !== undefined ? idx : -1;
    };

    const events = [];
    // Parse data rows (skip header, limit to 15000 to cover typical massive exports safely)
    const maxRows = Math.min(lines.length, 15001);
    for (let i = 1; i < maxRows; i++) {
      try {
        const fields = parseCSVLine(lines[i]);
        if (fields.length < 10) continue;

        const timestamp = parseWazuhTimestamp(fields[col('timestamp')] || fields[col('@timestamp')]);
        const ruleLevel = parseInt(fields[col('rule.level')] || '3', 10);
        const ruleDesc = fields[col('rule.description')] || '';
        const ruleId = fields[col('rule.id')] || '';
        const ruleGroups = fields[col('rule.groups')] || '';
        const agentName = fields[col('agent.name')] || 'unknown';
        const agentId = fields[col('agent.id')] || '000';
        const agentIp = fields[col('agent.ip')] || '127.0.0.1';
        const decoderName = fields[col('decoder.name')] || '';
        const fullLog = fields[col('full_log')] || '';
        const location = fields[col('location')] || '';
        const dataTitle = fields[col('data.title')] || '';
        const dataFile = fields[col('data.file')] || '';

        // Source IP extraction
        const srcIp = fields[col('data.srcip')] || agentIp || '127.0.0.1';
        const srcUser = fields[col('data.srcuser')] || '';
        const dstUser = fields[col('data.dstuser')] || '';

        // MITRE
        const mitreTactic = parseArrayField(fields[col('rule.mitre.tactic')]);
        const mitreTechnique = parseArrayField(fields[col('rule.mitre.technique')]);
        const mitreId = parseArrayField(fields[col('rule.mitre.id')]);

        // Compliance
        const complianceTags = {};
        const pciDss = fields[col('rule.pci_dss')];
        const nist = fields[col('rule.nist_800_53')];
        const gdpr = fields[col('rule.gdpr')];
        const hipaa = fields[col('rule.hipaa')];
        const tsc = fields[col('rule.tsc')];
        if (pciDss) complianceTags.pci_dss = parseArrayField(pciDss);
        if (nist) complianceTags.nist = parseArrayField(nist);
        if (gdpr) complianceTags.gdpr = parseArrayField(gdpr);
        if (hipaa) complianceTags.hipaa = parseArrayField(hipaa);
        if (tsc) complianceTags.tsc = parseArrayField(tsc);

        // OSCAP fields
        const oscapResult = fields[col('data.oscap.check.result')] || '';
        const oscapSeverity = fields[col('data.oscap.check.severity')] || '';
        const oscapTitle = fields[col('data.oscap.check.title')] || '';
        const oscapDesc = fields[col('data.oscap.check.description')] || '';

        // CIS fields
        const cisResult = fields[col('data.cis.result')] || '';
        const cisBenchmark = fields[col('data.cis.benchmark')] || '';
        const cisRuleTitle = fields[col('data.cis.rule_title')] || '';

        // Syscheck
        const syscheckEvent = fields[col('syscheck.event')] || '';
        const syscheckPath = fields[col('syscheck.path')] || '';

        // AWS
        const awsSeverity = fields[col('data.aws.severity')] || '';
        const awsType = fields[col('data.aws.type')] || '';
        const awsTitle = fields[col('data.aws.title')] || '';
        const awsDesc = fields[col('data.aws.description')] || '';

        // VirusTotal
        const vtFound = fields[col('data.virustotal.found')] || '';
        const vtMalicious = fields[col('data.virustotal.malicious')] || '';

        // GeoLocation
        const geoCountry = fields[col('GeoLocation.country_name')] || '';
        const geoCity = fields[col('GeoLocation.city_name')] || '';
        const geoLat = parseFloat(fields[col('GeoLocation.location.lat')] || '0');
        const geoLon = parseFloat(fields[col('GeoLocation.location.lon')] || '0');

        // Windows event data
        const winMessage = fields[col('data.win.system.message')] || '';
        const winEventId = fields[col('data.win.system.eventID')] || '';
        const winTargetUser = fields[col('data.win.eventdata.targetUserName')] || '';
        const winIpAddr = fields[col('data.win.eventdata.ipAddress')] || '';

        const attackType = classifyAttackType(ruleDesc, ruleGroups, ruleLevel, decoderName, fullLog);

        const event = {
          event_id: fields[col('_id')] || `CSV-${i}`,
          timestamp,
          source: 'csv_wazuh',
          agent_name: agentName,
          agent_id: agentId,
          user_id: srcUser || dstUser || 'system',
          user_role: srcUser ? 'user' : 'system',
          ip_address: winIpAddr || srcIp,
          event_type: decoderName || 'wazuh_alert',
          status: oscapResult || cisResult || (ruleLevel >= 8 ? 'alert' : 'info'),
          severity_level: ruleLevel,
          severity: levelToSeverity(ruleLevel),
          rule_id: ruleId,
          rule_description: ruleDesc,
          rule_groups: parseArrayField(ruleGroups),
          mitre_tactics: mitreTactic,
          mitre_techniques: mitreTechnique,
          mitre_ids: mitreId,
          compliance_tags: complianceTags,
          geo_country: geoCountry || 'Unknown',
          geo_city: geoCity || '',
          geo_lat: geoLat,
          geo_lon: geoLon,
          raw_data: {
            full_log: fullLog.substring(0, 500),
            decoder: decoderName,
            location,
            data_title: dataTitle,
            data_file: dataFile,
            oscap: oscapTitle ? { result: oscapResult, severity: oscapSeverity, title: oscapTitle, description: oscapDesc } : null,
            cis: cisRuleTitle ? { result: cisResult, benchmark: cisBenchmark, rule_title: cisRuleTitle } : null,
            syscheck: syscheckEvent ? { event: syscheckEvent, path: syscheckPath } : null,
            aws: awsType ? { severity: awsSeverity, type: awsType, title: awsTitle, description: awsDesc } : null,
            virustotal: vtFound ? { found: vtFound, malicious: vtMalicious } : null,
            windows: winEventId ? { eventId: winEventId, message: winMessage, targetUser: winTargetUser } : null,
            fired_times: parseInt(fields[col('rule.firedtimes')] || '0', 10),
          },
          is_attack: ruleLevel >= 7 || attackType !== 'generic_alert',
          attack_type: attackType,
        };

        events.push(event);
      } catch (rowErr) {
        // Skip malformed rows silently
      }
    }

    console.log(`[CSV Parser] Successfully parsed ${events.length} events from CSV`);

    // Log attack type distribution
    const typeCounts = {};
    events.forEach(e => { typeCounts[e.attack_type] = (typeCounts[e.attack_type] || 0) + 1; });
    console.log('[CSV Parser] Attack type distribution:', typeCounts);

    return events;
  } catch (err) {
    console.error('[CSV Parser] Error loading CSV:', err.message);
    return [];
  }
}

export default { loadCSVLogs };
