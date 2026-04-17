// clientCsvParser.js
// Parses standard Wazuh CSV exports strictly in the browser so we don't choke the Next.js API

export async function parseClientCSV(file, maxRows = 2000) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const text = e.target.result;
        const lines = text.split('\n');
        if (lines.length < 2) return resolve([]);

        const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
        const events = [];

        for (let i = 1; i < lines.length && events.length < maxRows; i++) {
          const line = lines[i];
          if (!line.trim()) continue;

          // Simple CSV line split (ignoring complex inner quotes for speed/size)
          const cols = line.split('","').map(c => c.replace(/^"|"$/g, ''));
          const raw = {};

          headers.forEach((h, idx) => {
            if (cols[idx] && cols[idx] !== '-') {
              try {
                if (cols[idx].startsWith('{') || cols[idx].startsWith('[')) {
                  raw[h] = JSON.parse(cols[idx].replace(/""/g, '"'));
                } else {
                  raw[h] = cols[idx];
                }
              } catch (e) {
                raw[h] = cols[idx];
              }
            }
          });

          // Map strictly required fields for the backend pipeline
          const ts = raw['@timestamp'] || raw['timestamp'] || new Date().toISOString();
          const ruleId = raw['rule.id'] || raw['rule_id'] || '0';
          const ruleLevel = parseInt(raw['rule.level'] || raw['rule_level'] || '0', 10);
          const eventType = raw['rule.groups'] || 'audit_event';
          const srcIp = raw['data.srcip'] || raw['data.aws.sourceIPAddress'] || 'unknown';
          const userName = raw['data.dstuser'] || raw['data.aws.userIdentity.userName'] || 'system';
          
          events.push({
            id: raw['id'] || `csv-${Date.now()}-${i}`,
            timestamp: ts,
            event_type: Array.isArray(eventType) ? eventType[0] : eventType,
            agent_id: raw['agent.id'] || 'unknown',
            agent_name: raw['agent.name'] || 'unknown',
            user_id: userName,
            ip_address: srcIp,
            geo_country: raw['GeoLocation.country_name'] || null,
            geo_city: raw['GeoLocation.city_name'] || null,
            geo_lat: parseFloat(raw['GeoLocation.location.lat']) || null,
            geo_lon: parseFloat(raw['GeoLocation.location.lon']) || null,
            status: raw['data.status'] || null,
            source: 'csv_wazuh',
            rule_id: ruleId,
            rule_level: ruleLevel,
            rule_description: raw['rule.description'] || raw['rule_description'] || '',
            raw_data: raw, // keep full raw data for pipeline enrichment
            is_attack: ruleLevel >= 7,
          });
        }
        resolve(events);
      } catch (err) {
        reject(err);
      }
    };
    reader.onerror = reject;
    reader.readAsText(file);
  });
}
