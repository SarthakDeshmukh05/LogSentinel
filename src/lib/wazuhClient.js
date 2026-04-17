// Wazuh Client — Fetches live data from Elasticsearch/OpenSearch via ngrok

const WAZUH_URL = 'https://ad4f-103-97-164-99.ngrok-free.app/wazuh-alerts-*/_search';
const WAZUH_USER = 'admin';
const WAZUH_PASS = 'SecretPassword';

export async function fetchWazuhAlerts(size = 500) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(`${WAZUH_URL}?size=${size}`, {
      method: 'GET',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${WAZUH_USER}:${WAZUH_PASS}`).toString('base64'),
        'Content-Type': 'application/json',
        'ngrok-skip-browser-warning': 'true',
      },
      cache: 'no-store',
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error(`Wazuh fetch failed: HTTP ${response.status} from ${WAZUH_URL}`);
      return null;
    }

    const data = await response.json();
    return data;
  } catch (err) {
    console.error('Wazuh connection error:', err.message);
    return null;
  }
}

export function normalizeWazuhAlerts(wazuhResponse) {
  if (!wazuhResponse?.hits?.hits) return [];

  return wazuhResponse.hits.hits.map((hit, idx) => {
    const source = hit._source || {};
    const rule = source.rule || {};
    const sca = source.data?.sca || {};
    const check = sca.check || {};
    const compliance = check.compliance || {};

    let mitreTactics = rule.mitre_tactics || [];
    let mitreTechniques = rule.mitre_techniques || [];

    // Handle comma-separated strings from compliance field
    if (typeof compliance.mitre_tactics === 'string') {
      mitreTactics = [...new Set([...mitreTactics, ...compliance.mitre_tactics.split(',')])];
    }
    if (typeof compliance.mitre_techniques === 'string') {
      mitreTechniques = [...new Set([...mitreTechniques, ...compliance.mitre_techniques.split(',')])];
    }

    // Build compliance tags
    const complianceTags = {};
    if (rule.pci_dss) complianceTags.pci_dss = rule.pci_dss;
    if (rule.hipaa) complianceTags.hipaa = rule.hipaa;
    if (rule.nist_sp_800_53 || rule.nist_800_53 || rule['nist_sp_800-53']) complianceTags.nist = rule.nist_sp_800_53 || rule.nist_800_53 || rule['nist_sp_800-53'];
    if (rule.gdpr) complianceTags.gdpr = rule.gdpr;
    if (rule.tsc) complianceTags.tsc = rule.tsc;
    if (rule.soc_2) complianceTags.soc_2 = rule.soc_2;
    if (rule.cis) complianceTags.cis = rule.cis;
    if (rule['iso_27001-2013']) complianceTags.iso_27001 = rule['iso_27001-2013'];

    // Geolocation fallback to Pune
    const geo = source.GeoLocation || {};
    const location = geo.location || {};
    
    return {
      event_id: hit._id || `WAZUH-${idx}`,
      timestamp: source['@timestamp'] || source.timestamp || new Date().toISOString(),
      source: 'wazuh_sca',
      agent_name: source.agent?.name || 'unknown',
      agent_id: source.agent?.id || '000',
      user_id: source.data?.srcuser || source.data?.win?.eventdata?.targetUserName || 'system',
      user_role: 'system',
      ip_address: source.data?.srcip || '127.0.0.1',
      event_type: sca.type || 'sca_check',
      status: check.result || 'unknown',
      severity_level: rule.level || 3,
      rule_id: rule.id || '',
      rule_description: rule.description || check.title || '',
      mitre_tactics: Array.isArray(mitreTactics) ? mitreTactics : (mitreTactics ? [mitreTactics] : []),
      mitre_techniques: Array.isArray(mitreTechniques) ? mitreTechniques : (mitreTechniques ? [mitreTechniques] : []),
      compliance_tags: complianceTags,
      geo_country: geo.country_name || (source.data?.srcip ? 'Unknown' : 'India'),
      geo_city: geo.city_name || (source.data?.srcip ? 'Unknown' : 'Pune'),
      geo_lat: location.lat || 18.5204,
      geo_lon: location.lon || 73.8567,
      raw_data: {
        sca_check_id: check.id,
        sca_check_title: check.title,
        sca_check_description: check.description,
        sca_check_rationale: check.rationale,
        sca_remediation: check.remediation,
        sca_policy: sca.policy,
        sca_scan_id: sca.scan_id,
        decoder: source.decoder?.name,
        location: source.location,
        fired_times: rule.firedtimes || 0,
        mitre_mitigations: rule.mitre_mitigations || [],
        cis_csc_v8: rule.cis_csc_v8 || [],
        cis_csc_v7: rule.cis_csc_v7 || [],
      },
      is_attack: false,
      attack_type: check.result === 'failed' ? 'sca_failure' : null,
    };
  });
}

export default { fetchWazuhAlerts, normalizeWazuhAlerts };
