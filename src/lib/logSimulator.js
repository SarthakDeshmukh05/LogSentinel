// Log Simulator — Generates realistic synthetic security logs with injected attack scenarios

const USERS = [
  { id: 'usr_001', name: 'john.smith', role: 'admin', department: 'IT', normalHours: [8, 18], normalIPs: ['192.168.1.10', '10.0.0.5'] },
  { id: 'usr_002', name: 'jane.doe', role: 'developer', department: 'Engineering', normalHours: [9, 20], normalIPs: ['192.168.1.20', '10.0.0.12'] },
  { id: 'usr_003', name: 'bob.wilson', role: 'analyst', department: 'Finance', normalHours: [8, 17], normalIPs: ['192.168.1.30'] },
  { id: 'usr_004', name: 'alice.chen', role: 'manager', department: 'Operations', normalHours: [7, 16], normalIPs: ['192.168.1.40', '10.0.0.8'] },
  { id: 'usr_005', name: 'charlie.brown', role: 'intern', department: 'Support', normalHours: [9, 17], normalIPs: ['192.168.1.50'] },
  { id: 'usr_006', name: 'diana.prince', role: 'sysadmin', department: 'IT', normalHours: [7, 19], normalIPs: ['192.168.1.60', '10.0.0.2'] },
  { id: 'usr_007', name: 'eve.martinez', role: 'developer', department: 'Engineering', normalHours: [10, 19], normalIPs: ['192.168.1.70'] },
  { id: 'usr_008', name: 'frank.jones', role: 'DBA', department: 'IT', normalHours: [8, 17], normalIPs: ['192.168.1.80', '10.0.0.20'] },
];

const KNOWN_IPS = [
  '192.168.1.10', '192.168.1.20', '192.168.1.30', '192.168.1.40',
  '192.168.1.50', '192.168.1.60', '192.168.1.70', '192.168.1.80',
  '10.0.0.2', '10.0.0.5', '10.0.0.8', '10.0.0.12', '10.0.0.20',
];

const FOREIGN_IPS = [
  { ip: '185.220.101.45', country: 'Germany', city: 'Frankfurt', lat: 50.11, lon: 8.68 },
  { ip: '103.224.182.251', country: 'China', city: 'Beijing', lat: 39.9, lon: 116.4 },
  { ip: '45.33.32.156', country: 'USA', city: 'San Francisco', lat: 37.77, lon: -122.42 },
  { ip: '91.218.114.11', country: 'Russia', city: 'Moscow', lat: 55.75, lon: 37.62 },
  { ip: '177.54.150.200', country: 'Brazil', city: 'São Paulo', lat: -23.55, lon: -46.63 },
  { ip: '156.146.56.100', country: 'Netherlands', city: 'Amsterdam', lat: 52.37, lon: 4.90 },
  { ip: '41.215.241.66', country: 'Nigeria', city: 'Lagos', lat: 6.45, lon: 3.40 },
  { ip: '222.186.15.200', country: 'China', city: 'Shanghai', lat: 31.23, lon: 121.47 },
  { ip: '89.248.167.131', country: 'Netherlands', city: 'Rotterdam', lat: 51.92, lon: 4.48 },
  { ip: '195.54.160.10', country: 'Ukraine', city: 'Kyiv', lat: 50.45, lon: 30.52 },
];

const LOCAL_GEO = { country: 'India', city: 'Pune', lat: 18.52, lon: 73.86 };

const EVENT_TYPES = ['login', 'logout', 'file_access', 'sudo', 'ssh_connection', 'api_call', 'db_query', 'config_change', 'service_restart', 'user_create'];

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomGaussian(mean, stdDev) {
  let u1 = Math.random(), u2 = Math.random();
  let z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return mean + z * stdDev;
}

function generateTimestamp(baseDate, hourMin, hourMax) {
  const date = new Date(baseDate);
  const hour = Math.max(0, Math.min(23, Math.round(randomGaussian((hourMin + hourMax) / 2, 1.5))));
  date.setHours(hour, randomInt(0, 59), randomInt(0, 59), randomInt(0, 999));
  return date;
}

function getIpGeo(ip) {
  const foreign = FOREIGN_IPS.find(f => f.ip === ip);
  if (foreign) return foreign;
  return { ip, ...LOCAL_GEO };
}

function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// Generate normal baseline events
function generateNormalEvents(baseDate, count = 200) {
  const events = [];
  for (let i = 0; i < count; i++) {
    const user = randomChoice(USERS);
    const ip = randomChoice(user.normalIPs);
    const timestamp = generateTimestamp(baseDate, user.normalHours[0], user.normalHours[1]);
    const eventType = randomChoice(EVENT_TYPES);
    const geo = getIpGeo(ip);

    events.push({
      event_id: `EVT-${Date.now()}-${randomInt(10000, 99999)}`,
      timestamp: timestamp.toISOString(),
      source: 'auth_log',
      agent_name: 'workstation-' + user.department.toLowerCase(),
      agent_id: `agent_${user.id}`,
      user_id: user.name,
      user_role: user.role,
      ip_address: ip,
      event_type: eventType,
      status: Math.random() > 0.05 ? 'success' : 'failed',
      severity_level: randomInt(1, 3),
      rule_id: '',
      rule_description: `Normal ${eventType} activity`,
      mitre_tactics: [],
      mitre_techniques: [],
      compliance_tags: {},
      geo_country: geo.country,
      geo_city: geo.city,
      geo_lat: geo.lat,
      geo_lon: geo.lon,
      raw_data: {},
      is_attack: false,
      attack_type: null,
    });
  }
  return events;
}

// Attack Scenario: Brute Force
function generateBruteForce(baseDate) {
  const targetUser = randomChoice(USERS);
  const attackerIp = randomChoice(FOREIGN_IPS);
  const baseTime = new Date(baseDate);
  baseTime.setHours(randomInt(1, 4), randomInt(0, 59));
  const events = [];

  for (let i = 0; i < randomInt(8, 20); i++) {
    const ts = new Date(baseTime.getTime() + i * randomInt(3000, 15000));
    events.push({
      event_id: `EVT-BF-${Date.now()}-${randomInt(10000, 99999)}`,
      timestamp: ts.toISOString(),
      source: 'auth_log',
      agent_name: 'gateway-01',
      agent_id: 'agent_gw01',
      user_id: targetUser.name,
      user_role: targetUser.role,
      ip_address: attackerIp.ip,
      event_type: 'login',
      status: i < (events.length || 8) - 1 ? 'failed' : (Math.random() > 0.7 ? 'success' : 'failed'),
      severity_level: 10,
      rule_id: 'R001',
      rule_description: 'Multiple failed login attempts detected',
      mitre_tactics: ['TA0006'],
      mitre_techniques: ['T1110', 'T1110.001'],
      compliance_tags: { pci_dss: '8.1.6', nist: 'AC-7' },
      geo_country: attackerIp.country,
      geo_city: attackerIp.city,
      geo_lat: attackerIp.lat,
      geo_lon: attackerIp.lon,
      raw_data: { failed_count: randomInt(8, 20), time_window_seconds: 120 },
      is_attack: true,
      attack_type: 'brute_force',
    });
  }
  return events;
}

// Attack Scenario: Impossible Travel
function generateImpossibleTravel(baseDate) {
  const user = randomChoice(USERS);
  const ts1 = new Date(baseDate);
  ts1.setHours(randomInt(8, 12), randomInt(0, 59));
  const ts2 = new Date(ts1.getTime() + randomInt(10, 45) * 60 * 1000);
  const foreignLoc = randomChoice(FOREIGN_IPS);
  const localIp = randomChoice(user.normalIPs);
  const distance = haversineDistance(LOCAL_GEO.lat, LOCAL_GEO.lon, foreignLoc.lat, foreignLoc.lon);
  const timeDiffHours = (ts2 - ts1) / (1000 * 60 * 60);
  const speed = Math.round(distance / timeDiffHours);

  return [
    {
      event_id: `EVT-IT-${Date.now()}-1`,
      timestamp: ts1.toISOString(),
      source: 'auth_log',
      agent_name: 'vpn-gateway',
      agent_id: 'agent_vpn01',
      user_id: user.name,
      user_role: user.role,
      ip_address: localIp,
      event_type: 'login',
      status: 'success',
      severity_level: 3,
      rule_id: '',
      rule_description: 'Normal login from known location',
      mitre_tactics: [],
      mitre_techniques: [],
      compliance_tags: {},
      geo_country: LOCAL_GEO.country,
      geo_city: LOCAL_GEO.city,
      geo_lat: LOCAL_GEO.lat,
      geo_lon: LOCAL_GEO.lon,
      raw_data: {},
      is_attack: false,
      attack_type: null,
    },
    {
      event_id: `EVT-IT-${Date.now()}-2`,
      timestamp: ts2.toISOString(),
      source: 'auth_log',
      agent_name: 'vpn-gateway',
      agent_id: 'agent_vpn01',
      user_id: user.name,
      user_role: user.role,
      ip_address: foreignLoc.ip,
      event_type: 'login',
      status: 'success',
      severity_level: 12,
      rule_id: 'R002',
      rule_description: `Impossible travel: ${LOCAL_GEO.city} → ${foreignLoc.city} in ${Math.round(timeDiffHours * 60)} minutes`,
      mitre_tactics: ['TA0001', 'TA0006'],
      mitre_techniques: ['T1078'],
      compliance_tags: { nist: 'AC-2', pci_dss: '10.2.5' },
      geo_country: foreignLoc.country,
      geo_city: foreignLoc.city,
      geo_lat: foreignLoc.lat,
      geo_lon: foreignLoc.lon,
      raw_data: {
        previous_location: LOCAL_GEO, current_location: foreignLoc,
        distance_km: Math.round(distance), time_diff_minutes: Math.round(timeDiffHours * 60),
        travel_speed_kmh: speed,
      },
      is_attack: true,
      attack_type: 'impossible_travel',
    }
  ];
}

// Attack Scenario: Off-Hours Login
function generateOffHoursLogin(baseDate) {
  const user = randomChoice(USERS);
  const foreignIp = randomChoice(FOREIGN_IPS);
  const ts = new Date(baseDate);
  ts.setHours(randomInt(1, 4), randomInt(0, 59));

  return [{
    event_id: `EVT-OH-${Date.now()}-${randomInt(10000, 99999)}`,
    timestamp: ts.toISOString(),
    source: 'auth_log',
    agent_name: 'ssh-gateway',
    agent_id: 'agent_ssh01',
    user_id: user.name,
    user_role: user.role,
    ip_address: foreignIp.ip,
    event_type: 'login',
    status: 'success',
    severity_level: 7,
    rule_id: 'R003',
    rule_description: `Off-hours login at ${ts.getHours()}:${String(ts.getMinutes()).padStart(2, '0')} from ${foreignIp.country}`,
    mitre_tactics: ['TA0001'],
    mitre_techniques: ['T1078'],
    compliance_tags: { nist: 'AC-2' },
    geo_country: foreignIp.country,
    geo_city: foreignIp.city,
    geo_lat: foreignIp.lat,
    geo_lon: foreignIp.lon,
    raw_data: { login_hour: ts.getHours(), normal_hours: user.normalHours },
    is_attack: true,
    attack_type: 'off_hours',
  }];
}

// Attack Scenario: Privilege Escalation
function generatePrivilegeEscalation(baseDate) {
  const user = USERS.find(u => u.role === 'intern') || randomChoice(USERS);
  const ts = new Date(baseDate);
  ts.setHours(randomInt(10, 15), randomInt(0, 59));

  return [{
    event_id: `EVT-PE-${Date.now()}-${randomInt(10000, 99999)}`,
    timestamp: ts.toISOString(),
    source: 'auth_log',
    agent_name: 'server-prod-01',
    agent_id: 'agent_prod01',
    user_id: user.name,
    user_role: user.role,
    ip_address: randomChoice(user.normalIPs),
    event_type: 'sudo',
    status: 'success',
    severity_level: 12,
    rule_id: 'R005',
    rule_description: `Privilege escalation: ${user.role} user executed sudo to root`,
    mitre_tactics: ['TA0004'],
    mitre_techniques: ['T1548', 'T1548.001'],
    compliance_tags: { nist: 'AC-6', pci_dss: '7.1', hipaa: '164.312(a)(1)' },
    geo_country: LOCAL_GEO.country,
    geo_city: LOCAL_GEO.city,
    geo_lat: LOCAL_GEO.lat,
    geo_lon: LOCAL_GEO.lon,
    raw_data: { from_user: user.name, to_user: 'root', command: '/bin/bash', user_role: user.role },
    is_attack: true,
    attack_type: 'privilege_escalation',
  }];
}

// Attack Scenario: Unknown IP Access
function generateUnknownIPAccess(baseDate) {
  const user = randomChoice(USERS);
  const unknownIp = randomChoice(FOREIGN_IPS);
  const ts = new Date(baseDate);
  ts.setHours(randomInt(6, 22), randomInt(0, 59));

  return [{
    event_id: `EVT-UI-${Date.now()}-${randomInt(10000, 99999)}`,
    timestamp: ts.toISOString(),
    source: 'auth_log',
    agent_name: 'firewall-01',
    agent_id: 'agent_fw01',
    user_id: user.name,
    user_role: user.role,
    ip_address: unknownIp.ip,
    event_type: 'login',
    status: 'success',
    severity_level: 8,
    rule_id: 'R004',
    rule_description: `Login from previously unseen IP: ${unknownIp.ip} (${unknownIp.country})`,
    mitre_tactics: ['TA0001'],
    mitre_techniques: ['T1078'],
    compliance_tags: { nist: 'AC-2', pci_dss: '10.2.5' },
    geo_country: unknownIp.country,
    geo_city: unknownIp.city,
    geo_lat: unknownIp.lat,
    geo_lon: unknownIp.lon,
    raw_data: { known_ips: user.normalIPs, unknown_ip: unknownIp.ip },
    is_attack: true,
    attack_type: 'unknown_ip',
  }];
}

// Attack Scenario: Rapid Event Burst
function generateEventBurst(baseDate) {
  const user = randomChoice(USERS);
  const baseTime = new Date(baseDate);
  baseTime.setHours(randomInt(0, 23), randomInt(0, 59));
  const events = [];

  for (let i = 0; i < randomInt(60, 100); i++) {
    const ts = new Date(baseTime.getTime() + i * randomInt(200, 800));
    events.push({
      event_id: `EVT-RB-${Date.now()}-${randomInt(10000, 99999)}`,
      timestamp: ts.toISOString(),
      source: 'auth_log',
      agent_name: 'api-server-01',
      agent_id: 'agent_api01',
      user_id: user.name,
      user_role: user.role,
      ip_address: randomChoice(user.normalIPs),
      event_type: 'api_call',
      status: Math.random() > 0.3 ? 'success' : 'failed',
      severity_level: 9,
      rule_id: 'R006',
      rule_description: `Rapid event burst: ${events.length + 60}+ events per minute`,
      mitre_tactics: ['TA0040'],
      mitre_techniques: ['T1499'],
      compliance_tags: {},
      geo_country: LOCAL_GEO.country,
      geo_city: LOCAL_GEO.city,
      geo_lat: LOCAL_GEO.lat,
      geo_lon: LOCAL_GEO.lon,
      raw_data: { events_per_minute: randomInt(60, 100) },
      is_attack: true,
      attack_type: 'event_burst',
    });
  }
  return events;
}

// Attack Scenario: Credential Stuffing (different users from same IP)
function generateCredentialStuffing(baseDate) {
  const attackerIp = randomChoice(FOREIGN_IPS);
  const baseTime = new Date(baseDate);
  baseTime.setHours(randomInt(2, 5), randomInt(0, 59));
  const events = [];

  const targetUsers = [...USERS].sort(() => Math.random() - 0.5).slice(0, randomInt(4, 7));
  for (let i = 0; i < targetUsers.length; i++) {
    const ts = new Date(baseTime.getTime() + i * randomInt(5000, 30000));
    events.push({
      event_id: `EVT-CS-${Date.now()}-${randomInt(10000, 99999)}`,
      timestamp: ts.toISOString(),
      source: 'auth_log',
      agent_name: 'gateway-01',
      agent_id: 'agent_gw01',
      user_id: targetUsers[i].name,
      user_role: targetUsers[i].role,
      ip_address: attackerIp.ip,
      event_type: 'login',
      status: 'failed',
      severity_level: 11,
      rule_id: 'R009',
      rule_description: `Credential stuffing: Failed auth for ${targetUsers.length} different users from ${attackerIp.ip}`,
      mitre_tactics: ['TA0006'],
      mitre_techniques: ['T1110', 'T1110.003'],
      compliance_tags: { pci_dss: '8.1.6', nist: 'AC-7' },
      geo_country: attackerIp.country,
      geo_city: attackerIp.city,
      geo_lat: attackerIp.lat,
      geo_lon: attackerIp.lon,
      raw_data: { target_users: targetUsers.map(u => u.name), attacker_ip: attackerIp.ip },
      is_attack: true,
      attack_type: 'credential_stuffing',
    });
  }
  return events;
}

// Main simulation function
export function generateSimulatedLogs(options = {}) {
  const {
    normalCount = 250,
    bruteForceCount = 2,
    impossibleTravelCount = 2,
    offHoursCount = 3,
    privEscCount = 2,
    unknownIPCount = 3,
    eventBurstCount = 1,
    credStuffingCount = 1,
    daysBack = 1,
  } = options;

  const now = new Date();
  const baseDate = new Date(now.getTime() - daysBack * 24 * 60 * 60 * 1000);
  let allEvents = [];

  // Normal events
  allEvents.push(...generateNormalEvents(baseDate, normalCount));

  // Attack scenarios
  for (let i = 0; i < bruteForceCount; i++) allEvents.push(...generateBruteForce(baseDate));
  for (let i = 0; i < impossibleTravelCount; i++) allEvents.push(...generateImpossibleTravel(baseDate));
  for (let i = 0; i < offHoursCount; i++) allEvents.push(...generateOffHoursLogin(baseDate));
  for (let i = 0; i < privEscCount; i++) allEvents.push(...generatePrivilegeEscalation(baseDate));
  for (let i = 0; i < unknownIPCount; i++) allEvents.push(...generateUnknownIPAccess(baseDate));
  for (let i = 0; i < eventBurstCount; i++) allEvents.push(...generateEventBurst(baseDate));
  for (let i = 0; i < credStuffingCount; i++) allEvents.push(...generateCredentialStuffing(baseDate));

  // Sort by timestamp
  allEvents.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  // Assign sequential IDs
  allEvents = allEvents.map((evt, idx) => ({
    ...evt,
    event_id: `EVT-${String(idx + 1).padStart(5, '0')}`,
  }));

  return allEvents;
}

export default { generateSimulatedLogs };
