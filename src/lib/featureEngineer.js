// Feature Engineer — Extracts 30+ features from normalized log events for ML detection

export function engineerFeatures(events) {
  if (!events || events.length === 0) return [];

  // Build baselines
  const userEventHistory = {};
  const userIPHistory = {};
  const userHourHistory = {};

  events.forEach(evt => {
    const uid = evt.user_id || 'unknown';
    if (!userEventHistory[uid]) userEventHistory[uid] = [];
    if (!userIPHistory[uid]) userIPHistory[uid] = new Set();
    if (!userHourHistory[uid]) userHourHistory[uid] = [];

    userEventHistory[uid].push(evt);
    if (evt.ip_address) userIPHistory[uid].add(evt.ip_address);
    const hour = new Date(evt.timestamp).getHours();
    userHourHistory[uid].push(hour);
  });

  // Compute mean login hour per user
  const userMeanHour = {};
  for (const [uid, hours] of Object.entries(userHourHistory)) {
    userMeanHour[uid] = hours.reduce((a, b) => a + b, 0) / hours.length;
  }

  // Count event types globally
  const eventTypeCounts = {};
  events.forEach(evt => {
    eventTypeCounts[evt.event_type] = (eventTypeCounts[evt.event_type] || 0) + 1;
  });
  const totalEvents = events.length;

  // Known IPs baseline set
  const allKnownIPs = new Set();
  events.filter(e => !e.is_attack).forEach(e => {
    if (e.ip_address) allKnownIPs.add(e.ip_address);
  });

  // Map events sequentially, maintaining history up to the current event to avoid O(N^2) filters
  const userHistory = {}; // uid -> array of past events
  
  return events.map((evt, idx) => {
    const tsTime = new Date(evt.timestamp).getTime();
    const ts = new Date(evt.timestamp);
    const uid = evt.user_id || 'unknown';
    
    if (!userHistory[uid]) userHistory[uid] = [];
    const prevUserEvents = userHistory[uid];

    // Temporal features
    const hour_of_day = ts.getHours();
    const minute_of_hour = ts.getMinutes();
    const day_of_week = ts.getDay();
    const is_weekend = day_of_week === 0 || day_of_week === 6 ? 1 : 0;
    const is_business_hours = (hour_of_day >= 8 && hour_of_day < 18) ? 1 : 0;
    const is_late_night = (hour_of_day >= 0 && hour_of_day < 5) ? 1 : 0;

    // Time since last event
    const time_since_last_event = prevUserEvents.length > 0
      ? (tsTime - prevUserEvents[prevUserEvents.length - 1].time) / 1000
      : 86400; // default to 24h if no prior event

    // Frequency features — Sliding windows (Walk backwards and break early)
    const fiveMinAgo = tsTime - 5 * 60 * 1000;
    const oneMinAgo = tsTime - 60 * 1000;
    const oneHourAgo = tsTime - 60 * 60 * 1000;

    let events_last_1min = 0;
    let events_last_5min = 0;
    let events_last_1hour = 0;
    let failed_events_last_5min = 0;
    let failed_events_last_1hour = 0;
    const uniqueIPsLastHour = new Set();

    for (let i = prevUserEvents.length - 1; i >= 0; i--) {
      const pastEvt = prevUserEvents[i];
      if (pastEvt.time < oneHourAgo) break; // Safely stop, list is chronologically sorted
      
      events_last_1hour++;
      if (pastEvt.ip) uniqueIPsLastHour.add(pastEvt.ip);
      if (pastEvt.status === 'failed') failed_events_last_1hour++;
      
      if (pastEvt.time >= fiveMinAgo) {
        events_last_5min++;
        if (pastEvt.status === 'failed') failed_events_last_5min++;
        
        if (pastEvt.time >= oneMinAgo) {
          events_last_1min++;
        }
      }
    }

    const unique_ips_last_1hour = uniqueIPsLastHour.size;
    const totalLast1h = events_last_1hour || 1;
    const failure_rate_last_1hour = failed_events_last_1hour / totalLast1h;

    // IP/Geo features
    const ip_is_known = allKnownIPs.has(evt.ip_address) ? 1 : 0;
    const ip_is_private = (evt.ip_address?.startsWith('192.168.') || evt.ip_address?.startsWith('10.') || evt.ip_address?.startsWith('172.')) ? 1 : 0;

    // Check country change from previous event
    let ip_country_changed = 0;
    let geo_distance_km = 0;
    let impossible_travel_flag = 0;
    let previous_location = null;
    
    if (prevUserEvents.length > 0) {
      const lastEvt = prevUserEvents[prevUserEvents.length - 1];
      if (lastEvt.country && evt.geo_country && lastEvt.country !== evt.geo_country) {
        ip_country_changed = 1;
      }
      if (lastEvt.lat && evt.geo_lat) {
        const R = 6371;
        const dLat = (evt.geo_lat - lastEvt.lat) * Math.PI / 180;
        const dLon = (evt.geo_lon - lastEvt.lon) * Math.PI / 180;
        const a = Math.sin(dLat / 2) ** 2 + Math.cos(lastEvt.lat * Math.PI / 180) * Math.cos(evt.geo_lat * Math.PI / 180) * Math.sin(dLon / 2) ** 2;
        geo_distance_km = R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

        const timeDiffHours = time_since_last_event / 3600;
        if (timeDiffHours > 0 && geo_distance_km > 500) {
          const speed = geo_distance_km / timeDiffHours;
          if (speed > 1000) {
            impossible_travel_flag = 1;
            previous_location = {
              city: lastEvt.city,
              country: lastEvt.country,
              lat: lastEvt.lat,
              lon: lastEvt.lon,
              ip: lastEvt.ip
            };
          }
        }
      }
    }
    
    // Add current event to history for future iterations
    prevUserEvents.push({
      time: tsTime,
      ip: evt.ip_address,
      status: evt.status,
      country: evt.geo_country,
      city: evt.geo_city,
      lat: evt.geo_lat,
      lon: evt.geo_lon
    });

    // SCA/Compliance features
    const sca_check_result = evt.status === 'passed' ? 0 : evt.status === 'failed' ? 1 : 2;
    const sca_severity_level = evt.severity_level || 0;
    const compliance_framework_count = Object.keys(evt.compliance_tags || {}).length;
    const has_remediation = evt.raw_data?.sca_remediation ? 1 : 0;
    const mitre_technique_count = (evt.mitre_techniques || []).length;
    const mitre_tactic_count = (evt.mitre_tactics || []).length;
    const fired_times = evt.raw_data?.fired_times || 0;

    // Behavioral features
    const meanHour = userMeanHour[uid] || 12;
    const login_hour_deviation = Math.abs(hour_of_day - meanHour);
    const event_type_rarity = 1 - ((eventTypeCounts[evt.event_type] || 0) / totalEvents);
    const is_status_failed = evt.status === 'failed' ? 1 : 0;

    // Privilege-related
    const privilege_level_change = (evt.event_type === 'sudo' || evt.attack_type === 'privilege_escalation') ? 1 : 0;

    return {
      ...evt,
      features: {
        // Temporal
        hour_of_day,
        minute_of_hour,
        day_of_week,
        is_weekend,
        is_business_hours,
        is_late_night,
        time_since_last_event: Math.min(time_since_last_event, 86400),
        // Frequency
        events_last_1min,
        events_last_5min,
        events_last_1hour,
        failed_events_last_5min,
        unique_ips_last_1hour,
        failure_rate_last_1hour,
        // IP/Geo
        ip_is_known,
        ip_is_private,
        ip_country_changed,
        geo_distance_km: Math.round(geo_distance_km),
        impossible_travel_flag,
        previous_location,
        // SCA/Compliance
        sca_check_result,
        sca_severity_level,
        compliance_framework_count,
        has_remediation,
        mitre_technique_count,
        mitre_tactic_count,
        fired_times,
        // Behavioral
        login_hour_deviation,
        event_type_rarity: Math.round(event_type_rarity * 1000) / 1000,
        is_status_failed,
        privilege_level_change,
      }
    };
  });
}

export function getFeatureVector(event) {
  const f = event.features;
  if (!f) return [];
  return [
    f.hour_of_day, f.is_weekend, f.is_business_hours, f.is_late_night,
    f.time_since_last_event / 86400,
    f.events_last_1min, f.events_last_5min, f.events_last_1hour,
    f.failed_events_last_5min, f.unique_ips_last_1hour, f.failure_rate_last_1hour,
    f.ip_is_known, f.ip_is_private, f.ip_country_changed,
    f.geo_distance_km / 20000, f.impossible_travel_flag,
    f.sca_check_result, f.sca_severity_level / 16,
    f.compliance_framework_count / 10, f.mitre_technique_count / 5,
    f.login_hour_deviation / 12, f.event_type_rarity,
    f.is_status_failed, f.privilege_level_change,
  ];
}

export const FEATURE_NAMES = [
  'hour_of_day', 'is_weekend', 'is_business_hours', 'is_late_night',
  'time_since_last_event', 'events_last_1min', 'events_last_5min',
  'events_last_1hour', 'failed_events_last_5min', 'unique_ips_last_1hour',
  'failure_rate_last_1hour', 'ip_is_known', 'ip_is_private', 'ip_country_changed',
  'geo_distance_km', 'impossible_travel_flag', 'sca_check_result',
  'sca_severity_level', 'compliance_framework_count', 'mitre_technique_count',
  'login_hour_deviation', 'event_type_rarity', 'is_status_failed',
  'privilege_level_change',
];

export default { engineerFeatures, getFeatureVector, FEATURE_NAMES };
