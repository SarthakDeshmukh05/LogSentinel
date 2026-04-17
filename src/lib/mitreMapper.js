// MITRE ATT&CK Framework Mapper
// Maps tactic and technique IDs to human-readable descriptions

const TACTICS = {
  'TA0001': { name: 'Initial Access', description: 'Techniques used to gain an initial foothold within a network.' },
  'TA0002': { name: 'Execution', description: 'Techniques that result in adversary-controlled code running on a local or remote system.' },
  'TA0003': { name: 'Persistence', description: 'Techniques used to maintain access to systems across restarts, changed credentials, and other interruptions.' },
  'TA0004': { name: 'Privilege Escalation', description: 'Techniques used to gain higher-level permissions on a system or network.' },
  'TA0005': { name: 'Defense Evasion', description: 'Techniques used to avoid detection throughout the attack lifecycle.' },
  'TA0006': { name: 'Credential Access', description: 'Techniques used to steal credentials like account names and passwords.' },
  'TA0007': { name: 'Discovery', description: 'Techniques used to gain knowledge about the system and internal network.' },
  'TA0008': { name: 'Lateral Movement', description: 'Techniques used to move through the network to access and control remote systems.' },
  'TA0009': { name: 'Collection', description: 'Techniques used to gather data of interest to the adversary.' },
  'TA0010': { name: 'Exfiltration', description: 'Techniques used to steal data from the network.' },
  'TA0011': { name: 'Command and Control', description: 'Techniques used to communicate with compromised systems to control them.' },
  'TA0040': { name: 'Impact', description: 'Techniques used to disrupt availability or compromise integrity by manipulating business and operational processes.' },
  'TA0042': { name: 'Resource Development', description: 'Techniques used to establish resources the adversary can use to support operations.' },
  'TA0043': { name: 'Reconnaissance', description: 'Techniques used to gather information for planning future adversary operations.' },
};

const TECHNIQUES = {
  'T1078': { name: 'Valid Accounts', tactic: 'TA0001', description: 'Adversaries may obtain and abuse credentials of existing accounts.' },
  'T1110': { name: 'Brute Force', tactic: 'TA0006', description: 'Adversaries may use brute force techniques to gain access to accounts.' },
  'T1110.001': { name: 'Password Guessing', tactic: 'TA0006', description: 'Adversaries may guess passwords using wordlists or common patterns.' },
  'T1110.003': { name: 'Password Spraying', tactic: 'TA0006', description: 'Adversaries may use a single password against many accounts.' },
  'T1036': { name: 'Masquerading', tactic: 'TA0005', description: 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate.' },
  'T1036.002': { name: 'Right-to-Left Override', tactic: 'TA0005', description: 'Adversaries may use RTLO characters to disguise file extensions.' },
  'T1036.003': { name: 'Rename System Utilities', tactic: 'TA0005', description: 'Adversaries may rename legitimate system utilities to evade detection.' },
  'T1036.004': { name: 'Masquerade Task or Service', tactic: 'TA0005', description: 'Adversaries may attempt to manipulate the name of a task or service.' },
  'T1036.005': { name: 'Match Legitimate Name or Location', tactic: 'TA0005', description: 'Adversaries may match or approximate names/locations of legitimate files.' },
  'T1082': { name: 'System Information Discovery', tactic: 'TA0007', description: 'An adversary may attempt to get detailed information about the operating system.' },
  'T1018': { name: 'Remote System Discovery', tactic: 'TA0007', description: 'Adversaries may attempt to get a listing of other systems by IP address or hostname.' },
  'T1200': { name: 'Hardware Additions', tactic: 'TA0001', description: 'Adversaries may introduce hardware devices to gain access.' },
  'T1204': { name: 'User Execution', tactic: 'TA0002', description: 'An adversary may rely upon specific actions by a user to gain execution.' },
  'T1204.002': { name: 'Malicious File', tactic: 'TA0002', description: 'An adversary may rely upon a user opening a malicious file.' },
  'T1499': { name: 'Endpoint Denial of Service', tactic: 'TA0040', description: 'Adversaries may perform endpoint DoS attacks to degrade or block services.' },
  'T1499.001': { name: 'OS Exhaustion Flood', tactic: 'TA0040', description: 'Adversaries may launch DoS attacks targeting the OS to exhaust resources.' },
  'T1548': { name: 'Abuse Elevation Control Mechanism', tactic: 'TA0004', description: 'Adversaries may circumvent mechanisms designed to control elevated privileges.' },
  'T1548.001': { name: 'Setuid and Setgid', tactic: 'TA0004', description: 'Adversaries may abuse setuid/setgid bits to gain elevated execution.' },
  'T1565': { name: 'Data Manipulation', tactic: 'TA0040', description: 'Adversaries may insert, delete, or manipulate data to influence outcomes.' },
  'T1565.001': { name: 'Stored Data Manipulation', tactic: 'TA0040', description: 'Adversaries may modify stored data to affect business processes.' },
  'T1592': { name: 'Gather Victim Host Information', tactic: 'TA0043', description: 'Adversaries may gather information about the victim host.' },
  'T1592.004': { name: 'Client Configurations', tactic: 'TA0043', description: 'Adversaries may gather information about client configurations.' },
  'T1059': { name: 'Command and Scripting Interpreter', tactic: 'TA0002', description: 'Adversaries may abuse command and script interpreters to execute commands.' },
  'T1021': { name: 'Remote Services', tactic: 'TA0008', description: 'Adversaries may use valid accounts to log into a service specifically designed to accept remote connections.' },
  'T1021.004': { name: 'SSH', tactic: 'TA0008', description: 'Adversaries may use valid accounts to log into remote machines using SSH.' },
  'T1531': { name: 'Account Access Removal', tactic: 'TA0040', description: 'Adversaries may interrupt availability by inhibiting access to accounts.' },
};

const MITIGATIONS = {
  'M1022': { name: 'Restrict File and Directory Permissions', description: 'Restrict access to file and directory by setting proper permissions.' },
  'M1038': { name: 'Execution Prevention', description: 'Block execution of code on a system through policies or tools.' },
  'M1032': { name: 'Multi-factor Authentication', description: 'Use multi-factor authentication to reduce credential theft risk.' },
  'M1036': { name: 'Account Use Policies', description: 'Configure features related to account use like lockout policies.' },
  'M1026': { name: 'Privileged Account Management', description: 'Manage the creation, modification, use, and permissions of privileged accounts.' },
};

export function getTacticInfo(tacticId) {
  return TACTICS[tacticId] || { name: tacticId, description: 'Unknown tactic' };
}

export function getTechniqueInfo(techniqueId) {
  return TECHNIQUES[techniqueId] || { name: techniqueId, description: 'Unknown technique' };
}

export function getMitigationInfo(mitigationId) {
  return MITIGATIONS[mitigationId] || { name: mitigationId, description: 'Unknown mitigation' };
}

export function getTechniqueUrl(techniqueId) {
  const base = 'https://attack.mitre.org/techniques/';
  const parts = techniqueId.split('.');
  if (parts.length === 2) {
    return `${base}${parts[0]}/${parts[1].padStart(3, '0')}/`;
  }
  return `${base}${techniqueId}/`;
}

export function enrichWithMitre(alert) {
  const enriched = { ...alert };
  
  if (alert.mitre_tactics && Array.isArray(alert.mitre_tactics)) {
    enriched.mitre_tactic_details = alert.mitre_tactics.map(id => ({
      id,
      ...getTacticInfo(id)
    }));
  }
  
  if (alert.mitre_techniques && Array.isArray(alert.mitre_techniques)) {
    enriched.mitre_technique_details = alert.mitre_techniques.map(id => ({
      id,
      ...getTechniqueInfo(id),
      url: getTechniqueUrl(id)
    }));
  }
  
  return enriched;
}

export function getMitreHeatmapData(alerts) {
  const tacticCounts = {};
  const techniqueCounts = {};
  
  for (const alert of alerts) {
    if (alert.mitre_tactics) {
      for (const tactic of alert.mitre_tactics) {
        tacticCounts[tactic] = (tacticCounts[tactic] || 0) + 1;
      }
    }
    if (alert.mitre_techniques) {
      for (const technique of alert.mitre_techniques) {
        techniqueCounts[technique] = (techniqueCounts[technique] || 0) + 1;
      }
    }
  }
  
  return {
    tactics: Object.entries(tacticCounts).map(([id, count]) => ({
      id,
      ...getTacticInfo(id),
      count
    })).sort((a, b) => b.count - a.count),
    techniques: Object.entries(techniqueCounts).map(([id, count]) => ({
      id,
      ...getTechniqueInfo(id),
      url: getTechniqueUrl(id),
      count
    })).sort((a, b) => b.count - a.count)
  };
}

export default {
  getTacticInfo,
  getTechniqueInfo,
  getMitigationInfo,
  getTechniqueUrl,
  enrichWithMitre,
  getMitreHeatmapData,
  TACTICS,
  TECHNIQUES,
  MITIGATIONS
};
