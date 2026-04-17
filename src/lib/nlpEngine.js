// NLP Engine — Natural Language Processing for SIEM query translation
// Handles intent classification, entity extraction, temporal parsing, and DSL generation

// ============ INTENT DEFINITIONS ============
const INTENTS = [
  { id: 'search_failed_logins', patterns: ['failed login', 'failed auth', 'authentication fail', 'login fail', 'unsuccessful login', 'bad login', 'wrong password'], category: 'investigation' },
  { id: 'search_successful_logins', patterns: ['successful login', 'success auth', 'logged in', 'authenticated successfully'], category: 'investigation' },
  { id: 'search_brute_force', patterns: ['brute force', 'brute-force', 'password spray', 'credential guess', 'repeated failed'], category: 'investigation' },
  { id: 'search_malware', patterns: ['malware', 'virus', 'trojan', 'ransomware', 'worm', 'spyware', 'malicious file', 'infected'], category: 'investigation' },
  { id: 'search_suspicious', patterns: ['suspicious', 'anomal', 'unusual', 'abnormal', 'strange', 'weird', 'odd'], category: 'investigation' },
  { id: 'search_vpn', patterns: ['vpn', 'virtual private network', 'tunnel', 'remote access'], category: 'investigation' },
  { id: 'search_firewall', patterns: ['firewall', 'blocked', 'dropped', 'denied', 'rejected', 'fw'], category: 'investigation' },
  { id: 'search_privilege_escalation', patterns: ['privilege escalation', 'sudo', 'root access', 'admin access', 'elevated', 'priv esc'], category: 'investigation' },
  { id: 'search_sca', patterns: ['sca', 'security config', 'compliance', 'configuration assessment', 'cis benchmark', 'hardening'], category: 'investigation' },
  { id: 'search_network', patterns: ['network', 'connection', 'traffic', 'packet', 'port scan', 'port'], category: 'investigation' },
  { id: 'search_user', patterns: ['user activity', 'user action', 'what did user', 'show me user', 'find user'], category: 'investigation' },
  { id: 'search_agent', patterns: ['agent', 'endpoint', 'host', 'machine', 'server'], category: 'investigation' },
  { id: 'search_mfa', patterns: ['mfa', 'multi-factor', 'two-factor', '2fa', 'otp'], category: 'investigation' },
  { id: 'search_rule', patterns: ['rule', 'alert rule', 'detection rule', 'wazuh rule', 'rule id'], category: 'investigation' },
  { id: 'search_mitre', patterns: ['mitre', 'att&ck', 'technique', 'tactic', 'tta'], category: 'investigation' },
  { id: 'search_ip', patterns: ['ip address', 'source ip', 'from ip', 'ip '], category: 'investigation' },
  { id: 'generate_report', patterns: ['report', 'summary', 'summarize', 'generate report', 'overview', 'brief', 'briefing'], category: 'report' },
  { id: 'count_events', patterns: ['how many', 'count', 'total number', 'how much'], category: 'aggregation' },
  { id: 'top_items', patterns: ['top', 'most common', 'most frequent', 'highest', 'worst', 'leading'], category: 'aggregation' },
  { id: 'trend', patterns: ['trend', 'over time', 'timeline', 'history', 'pattern', 'chart'], category: 'aggregation' },
  { id: 'filter', patterns: ['filter', 'only', 'just', 'exclude', 'narrow', 'restrict', 'limit to'], category: 'filter' },
  { id: 'help', patterns: ['help', 'what can you', 'how to', 'example', 'commands'], category: 'system' },
];

// ============ ENTITY EXTRACTORS ============
const TEMPORAL_PATTERNS = [
  { pattern: /last\s+(\d+)\s+minute/i, unit: 'minute' },
  { pattern: /last\s+(\d+)\s+hour/i, unit: 'hour' },
  { pattern: /last\s+(\d+)\s+day/i, unit: 'day' },
  { pattern: /last\s+(\d+)\s+week/i, unit: 'week' },
  { pattern: /last\s+(\d+)\s+month/i, unit: 'month' },
  { pattern: /past\s+(\d+)\s+minute/i, unit: 'minute' },
  { pattern: /past\s+(\d+)\s+hour/i, unit: 'hour' },
  { pattern: /past\s+(\d+)\s+day/i, unit: 'day' },
  { pattern: /past\s+(\d+)\s+week/i, unit: 'week' },
  { pattern: /past\s+(\d+)\s+month/i, unit: 'month' },
  { pattern: /yesterday/i, unit: 'day', value: 1, label: 'yesterday' },
  { pattern: /today/i, unit: 'day', value: 0, label: 'today' },
  { pattern: /this week/i, unit: 'week', value: 0, label: 'this week' },
  { pattern: /this month/i, unit: 'month', value: 0, label: 'this month' },
  { pattern: /last week/i, unit: 'week', value: 1, label: 'last week' },
  { pattern: /last month/i, unit: 'month', value: 1, label: 'last month' },
  { pattern: /last hour/i, unit: 'hour', value: 1, label: 'last hour' },
  { pattern: /last\s+24\s+hours/i, unit: 'hour', value: 24, label: 'last 24 hours' },
];

const SEVERITY_KEYWORDS = {
  critical: [15, 16], high: [11, 12, 13, 14], medium: [7, 8, 9, 10], low: [0, 1, 2, 3, 4, 5, 6],
};

// ============ NLP PARSER ============
export function parseQuery(text, context = {}) {
  const lower = text.toLowerCase().trim();

  // Classify intent
  let bestIntent = null;
  let bestScore = 0;

  for (const intent of INTENTS) {
    for (const pattern of intent.patterns) {
      if (lower.includes(pattern)) {
        const score = pattern.length / lower.length + (pattern.split(' ').length * 0.2);
        if (score > bestScore) {
          bestScore = score;
          bestIntent = intent;
        }
      }
    }
  }

  // Extract temporal entity
  let timeRange = null;
  for (const tp of TEMPORAL_PATTERNS) {
    const match = lower.match(tp.pattern);
    if (match) {
      const value = tp.value !== undefined ? tp.value : parseInt(match[1]);
      const unitMap = { minute: 'm', hour: 'h', day: 'd', week: 'w', month: 'M' };
      if (value === 0) {
        timeRange = { gte: `now/${unitMap[tp.unit]}`, label: tp.label || `this ${tp.unit}` };
      } else {
        timeRange = { gte: `now-${value}${unitMap[tp.unit]}`, label: tp.label || `last ${value} ${tp.unit}(s)` };
      }
      break;
    }
  }

  // Default time range from context or last 24h
  if (!timeRange) {
    timeRange = context.lastTimeRange || { gte: 'now-24h', label: 'last 24 hours' };
  }

  // Extract severity
  let severityFilter = null;
  for (const [level, range] of Object.entries(SEVERITY_KEYWORDS)) {
    if (lower.includes(level)) {
      severityFilter = { level, gte: range[0], lte: range[range.length - 1] };
      break;
    }
  }

  // Extract IP address
  const ipMatch = lower.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  const ipAddress = ipMatch ? ipMatch[1] : null;

  // Extract user
  const userMatch = lower.match(/(?:user|username|account)\s+["\']?(\w+)["\']?/i);
  const user = userMatch ? userMatch[1] : (context.lastUser || null);

  // Extract agent/host
  const agentMatch = lower.match(/(?:agent|host|server|machine|endpoint)\s+["\']?([.\w-]+)["\']?/i);
  const agent = agentMatch ? agentMatch[1] : (context.lastAgent || null);

  // Extract rule ID
  const ruleMatch = lower.match(/rule\s*(?:id)?\s*(\d+)/i);
  const ruleId = ruleMatch ? ruleMatch[1] : null;

  // Extract MITRE technique
  const mitreMatch = lower.match(/[tT](\d{4}(?:\.\d{3})?)/);
  const mitreTechnique = mitreMatch ? `T${mitreMatch[1]}` : null;

  // Extract count for top-N queries
  const topNMatch = lower.match(/top\s+(\d+)/i);
  const topN = topNMatch ? parseInt(topNMatch[1]) : 10;

  // Check if this is a follow-up (uses context from prior query)
  const isFollowUp = bestIntent?.category === 'filter' ||
    lower.startsWith('and ') ||
    lower.startsWith('also ') ||
    lower.startsWith('but ') ||
    lower.startsWith('now ') ||
    lower.startsWith('what about');

  return {
    raw: text,
    intent: bestIntent || { id: 'search_general', category: 'investigation', patterns: [] },
    entities: {
      timeRange,
      severity: severityFilter,
      ipAddress,
      user,
      agent,
      ruleId,
      mitreTechnique,
      topN,
    },
    isFollowUp,
    context,
  };
}

// ============ ELASTICSEARCH DSL QUERY GENERATOR ============
export function generateElasticsearchQuery(parsed) {
  const { intent, entities, isFollowUp, context } = parsed;
  const must = [];
  const filter = [];

  // Time range filter
  if (entities.timeRange) {
    filter.push({
      range: {
        '@timestamp': {
          gte: entities.timeRange.gte,
          lte: 'now',
        },
      },
    });
  }

  // Intent-specific query clauses
  switch (intent.id) {
    case 'search_failed_logins':
      must.push({ match: { 'data.win.system.message': 'failed' } });
      filter.push({
        bool: {
          should: [
            { match: { 'rule.description': 'authentication failure' } },
            { match: { 'rule.description': 'failed login' } },
            { range: { 'rule.level': { gte: 5 } } },
          ],
          minimum_should_match: 1,
        },
      });
      break;

    case 'search_successful_logins':
      must.push({
        bool: {
          should: [
            { match: { 'rule.description': 'successful login' } },
            { match: { 'rule.description': 'session opened' } },
            { match: { 'rule.description': 'authenticated' } },
          ],
          minimum_should_match: 1,
        },
      });
      break;

    case 'search_brute_force':
      filter.push({ range: { 'rule.level': { gte: 10 } } });
      must.push({
        bool: {
          should: [
            { match_phrase: { 'rule.description': 'brute force' } },
            { match: { 'rule.description': 'multiple authentication failures' } },
            { terms: { 'rule.id': ['5551', '5712', '5720', '5503', '5504'] } },
          ],
          minimum_should_match: 1,
        },
      });
      break;

    case 'search_malware':
      must.push({
        bool: {
          should: [
            { match: { 'rule.groups': 'malware' } },
            { match: { 'rule.description': 'malware' } },
            { match: { 'rule.description': 'virus' } },
            { match: { 'syscheck.event': 'modified' } },
          ],
          minimum_should_match: 1,
        },
      });
      break;

    case 'search_suspicious':
      filter.push({ range: { 'rule.level': { gte: 8 } } });
      break;

    case 'search_vpn':
      must.push({
        bool: {
          should: [
            { match: { 'rule.description': 'vpn' } },
            { match: { 'rule.groups': 'vpn' } },
            { match: { 'data.srcip': 'vpn' } },
          ],
          minimum_should_match: 1,
        },
      });
      break;

    case 'search_firewall':
      must.push({
        bool: {
          should: [
            { match: { 'rule.groups': 'firewall' } },
            { match: { 'rule.description': 'dropped' } },
            { match: { 'rule.description': 'blocked' } },
            { match: { 'rule.description': 'denied' } },
          ],
          minimum_should_match: 1,
        },
      });
      break;

    case 'search_privilege_escalation':
      must.push({
        bool: {
          should: [
            { match: { 'rule.description': 'sudo' } },
            { match: { 'rule.description': 'privilege' } },
            { match: { 'rule.groups': 'authentication_success' } },
            { terms: { 'rule.id': ['5401', '5402', '5403'] } },
          ],
          minimum_should_match: 1,
        },
      });
      break;

    case 'search_sca':
      must.push({
        bool: {
          should: [
            { match: { 'rule.groups': 'sca' } },
            { exists: { field: 'data.sca.check.result' } },
          ],
          minimum_should_match: 1,
        },
      });
      break;

    case 'search_network':
      must.push({
        bool: {
          should: [
            { match: { 'rule.groups': 'network' } },
            { exists: { field: 'data.srcip' } },
            { match: { 'rule.description': 'connection' } },
          ],
          minimum_should_match: 1,
        },
      });
      break;

    case 'search_mitre':
      if (entities.mitreTechnique) {
        must.push({ match: { 'rule.mitre.id': entities.mitreTechnique } });
      } else {
        must.push({ exists: { field: 'rule.mitre.id' } });
      }
      break;

    case 'search_rule':
      if (entities.ruleId) {
        filter.push({ term: { 'rule.id': entities.ruleId } });
      }
      break;

    default:
      // General search — use the raw query as a multi_match
      const cleanQuery = parsed.raw.replace(/['"]/g, '').substring(0, 200);
      must.push({
        multi_match: {
          query: cleanQuery,
          fields: ['rule.description', 'rule.groups', 'agent.name', 'data.srcip', 'data.dstip'],
          type: 'best_fields',
          fuzziness: 'AUTO',
        },
      });
      break;
  }

  // Apply entity filters
  if (entities.severity) {
    filter.push({
      range: {
        'rule.level': { gte: entities.severity.gte, lte: entities.severity.lte },
      },
    });
  }

  if (entities.ipAddress) {
    must.push({
      bool: {
        should: [
          { match: { 'data.srcip': entities.ipAddress } },
          { match: { 'data.dstip': entities.ipAddress } },
          { match: { 'agent.ip': entities.ipAddress } },
        ],
        minimum_should_match: 1,
      },
    });
  }

  if (entities.user) {
    must.push({
      bool: {
        should: [
          { match: { 'data.srcuser': entities.user } },
          { match: { 'data.dstuser': entities.user } },
          { match: { 'data.win.eventdata.targetUserName': entities.user } },
        ],
        minimum_should_match: 1,
      },
    });
  }

  if (entities.agent) {
    must.push({
      bool: {
        should: [
          { match: { 'agent.name': entities.agent } },
          { match: { 'agent.id': entities.agent } },
        ],
        minimum_should_match: 1,
      },
    });
  }

  // Merge with context filters for follow-ups
  const contextFilters = (isFollowUp && context.lastQuery?.filter) || [];

  // Build the final query
  const size = intent.category === 'aggregation' ? 0 : 25;
  const query = {
    size,
    query: {
      bool: {
        must: [...must],
        filter: [...filter, ...contextFilters],
      },
    },
    sort: [{ '@timestamp': { order: 'desc' } }],
  };

  // Add aggregations for aggregation intents
  if (intent.category === 'aggregation' || intent.id === 'generate_report') {
    query.aggs = {
      by_rule_level: {
        terms: { field: 'rule.level', size: 16, order: { _key: 'desc' } },
      },
      by_agent: {
        terms: { field: 'agent.name', size: entities.topN },
      },
      by_rule_description: {
        terms: { field: 'rule.description.keyword', size: entities.topN },
      },
      over_time: {
        date_histogram: {
          field: '@timestamp',
          calendar_interval: 'hour',
        },
      },
    };

    if (intent.id === 'top_items' || intent.id === 'generate_report') {
      query.aggs.by_mitre_tactic = {
        terms: { field: 'rule.mitre.tactic', size: entities.topN },
      };
      query.aggs.by_mitre_technique = {
        terms: { field: 'rule.mitre.id', size: entities.topN },
      };
      query.aggs.by_source_ip = {
        terms: { field: 'data.srcip', size: entities.topN },
      };
    }
  }

  return query;
}

// ============ RESPONSE FORMATTER ============
export function formatResponse(esResponse, parsed) {
  const { intent, entities } = parsed;
  const hits = esResponse?.hits?.hits || [];
  const totalHits = esResponse?.hits?.total?.value || hits.length;
  const aggs = esResponse?.aggregations || {};

  let narrative = '';
  let data = { hits: [], aggregations: {}, charts: [] };

  // Format hits
  data.hits = hits.slice(0, 20).map(hit => {
    const s = hit._source || {};
    return {
      id: hit._id,
      timestamp: s['@timestamp'],
      agent: s.agent?.name || 'unknown',
      rule_id: s.rule?.id,
      rule_level: s.rule?.level,
      rule_description: s.rule?.description?.substring(0, 150),
      rule_groups: s.rule?.groups?.join(', '),
      mitre: s.rule?.mitre?.id?.join(', ') || '',
      src_ip: s.data?.srcip || '',
      src_user: s.data?.srcuser || '',
      sca_result: s.data?.sca?.check?.result || '',
      sca_title: s.data?.sca?.check?.title?.substring(0, 100) || '',
    };
  });

  // Format aggregations
  for (const [key, agg] of Object.entries(aggs)) {
    if (agg.buckets) {
      data.aggregations[key] = agg.buckets.map(b => ({
        key: b.key_as_string || b.key,
        count: b.doc_count,
      }));
    }
  }

  // Generate narrative based on intent
  switch (intent.id) {
    case 'search_failed_logins':
      narrative = `🔍 Found **${totalHits} failed login events** in ${entities.timeRange?.label || 'the selected period'}.`;
      if (totalHits > 50) {
        narrative += ` ⚠️ This is a high volume — investigate potential brute force activity.`;
      }
      if (data.hits.length > 0) {
        const agents = [...new Set(data.hits.map(h => h.agent))];
        narrative += `\n\nAffected agents: **${agents.join(', ')}**`;
        const ips = [...new Set(data.hits.map(h => h.src_ip).filter(Boolean))];
        if (ips.length > 0) narrative += `\nSource IPs: \`${ips.slice(0, 5).join('`, `')}\``;
      }
      break;

    case 'search_brute_force':
      narrative = `🔴 Found **${totalHits} potential brute force events** in ${entities.timeRange?.label || 'the selected period'}.`;
      if (totalHits === 0) {
        narrative = `✅ No brute force attempts detected in ${entities.timeRange?.label || 'the selected period'}.`;
      }
      break;

    case 'search_malware':
      narrative = totalHits > 0
        ? `🦠 **${totalHits} malware-related events** detected in ${entities.timeRange?.label || 'the selected period'}. Immediate investigation recommended.`
        : `✅ No malware events found in ${entities.timeRange?.label || 'the selected period'}.`;
      break;

    case 'search_sca':
      narrative = `📋 Found **${totalHits} SCA (Security Configuration Assessment) events** in ${entities.timeRange?.label || 'the selected period'}.`;
      const failed = data.hits.filter(h => h.sca_result === 'failed').length;
      const passed = data.hits.filter(h => h.sca_result === 'passed').length;
      if (failed > 0 || passed > 0) {
        narrative += `\n\n| Status | Count |\n|--------|-------|\n| ✅ Passed | ${passed} |\n| ❌ Failed | ${failed} |`;
      }
      break;

    case 'search_privilege_escalation':
      narrative = totalHits > 0
        ? `⚠️ **${totalHits} privilege escalation events** detected. Review sudo usage and elevated access.`
        : `✅ No privilege escalation events found.`;
      break;

    case 'count_events':
      narrative = `📊 **Total: ${totalHits} events** found in ${entities.timeRange?.label || 'the selected period'}.`;
      break;

    case 'top_items': {
      narrative = `📊 **Top results** from ${entities.timeRange?.label || 'the selected period'}:\n\n`;
      if (data.aggregations.by_rule_description?.length > 0) {
        narrative += `**Top Alert Types:**\n`;
        data.aggregations.by_rule_description.slice(0, 5).forEach((item, i) => {
          narrative += `${i + 1}. ${item.key} — **${item.count}** events\n`;
        });
      }
      if (data.aggregations.by_agent?.length > 0) {
        narrative += `\n**Top Agents:**\n`;
        data.aggregations.by_agent.slice(0, 5).forEach((item, i) => {
          narrative += `${i + 1}. ${item.key} — **${item.count}** events\n`;
        });
      }
      break;
    }

    case 'generate_report': {
      narrative = `# 📄 Security Report — ${entities.timeRange?.label || 'Last 24 Hours'}\n\n`;
      narrative += `**Total Events Analyzed:** ${totalHits}\n\n`;

      if (data.aggregations.by_rule_level?.length > 0) {
        narrative += `## Severity Distribution\n| Level | Count |\n|-------|-------|\n`;
        data.aggregations.by_rule_level.forEach(item => {
          const label = item.key >= 12 ? '🔴 Critical' : item.key >= 8 ? '🟠 High' : item.key >= 4 ? '🟡 Medium' : '🟢 Low';
          narrative += `| ${label} (${item.key}) | ${item.count} |\n`;
        });
      }

      if (data.aggregations.by_agent?.length > 0) {
        narrative += `\n## Top Agents\n`;
        data.aggregations.by_agent.slice(0, 5).forEach((item, i) => {
          narrative += `${i + 1}. **${item.key}** — ${item.count} events\n`;
        });
      }

      if (data.aggregations.by_mitre_tactic?.length > 0) {
        narrative += `\n## MITRE ATT&CK Tactics\n`;
        data.aggregations.by_mitre_tactic.forEach((item, i) => {
          narrative += `- **${item.key}** — ${item.count} events\n`;
        });
      }
      break;
    }

    case 'help':
      narrative = `## 🤖 SIEM Assistant — Available Queries\n\n`;
      narrative += `**Investigation:**\n`;
      narrative += `- "Show failed login attempts in the last 24 hours"\n`;
      narrative += `- "What suspicious activity occurred yesterday?"\n`;
      narrative += `- "Find brute force attacks this week"\n`;
      narrative += `- "Show privilege escalation events for user admin"\n`;
      narrative += `- "Search for malware detections last month"\n`;
      narrative += `- "Show SCA compliance failures"\n`;
      narrative += `- "Find events from IP 192.168.1.1"\n\n`;
      narrative += `**Reports:**\n`;
      narrative += `- "Generate a security summary for this week"\n`;
      narrative += `- "Create a report of high severity alerts"\n\n`;
      narrative += `**Aggregations:**\n`;
      narrative += `- "How many failed logins today?"\n`;
      narrative += `- "Top 10 alert types this month"\n`;
      narrative += `- "Show event trends over the last week"\n\n`;
      narrative += `**Follow-ups:** After any query, you can refine:\n`;
      narrative += `- "Filter only VPN-related"\n`;
      narrative += `- "Now show only critical severity"\n`;
      narrative += `- "What about last week instead?"`;
      data.skipQuery = true;
      break;

    default:
      narrative = totalHits > 0
        ? `🔍 Found **${totalHits} events** matching your query in ${entities.timeRange?.label || 'the selected period'}.`
        : `ℹ️ No events found matching your query in ${entities.timeRange?.label || 'the selected period'}. Try broadening the time range or adjusting your search terms.`;
      break;
  }

  // Build chart data from aggregations
  if (data.aggregations.over_time?.length > 0) {
    data.charts.push({
      type: 'timeline',
      title: 'Events Over Time',
      data: data.aggregations.over_time.map(b => ({ time: b.key, count: b.count })),
    });
  }
  if (data.aggregations.by_rule_level?.length > 0) {
    data.charts.push({
      type: 'bar',
      title: 'By Severity Level',
      data: data.aggregations.by_rule_level.map(b => ({ label: `Level ${b.key}`, count: b.count })),
    });
  }

  return { narrative, data, totalHits, query_executed: true };
}

// ============ CONTEXT MANAGER ============
export class ConversationContext {
  constructor() {
    this.history = [];
    this.lastTimeRange = null;
    this.lastUser = null;
    this.lastAgent = null;
    this.lastIntent = null;
    this.lastQuery = null;
  }

  update(parsed, esQuery, response) {
    this.lastTimeRange = parsed.entities.timeRange;
    if (parsed.entities.user) this.lastUser = parsed.entities.user;
    if (parsed.entities.agent) this.lastAgent = parsed.entities.agent;
    this.lastIntent = parsed.intent;
    this.lastQuery = esQuery;

    this.history.push({
      timestamp: new Date().toISOString(),
      userQuery: parsed.raw,
      intent: parsed.intent.id,
      totalHits: response?.totalHits || 0,
    });

    // Keep last 20 turns
    if (this.history.length > 20) this.history.shift();
  }

  toJSON() {
    return {
      history: this.history,
      lastTimeRange: this.lastTimeRange,
      lastUser: this.lastUser,
      lastAgent: this.lastAgent,
      lastIntent: this.lastIntent?.id,
    };
  }

  static fromJSON(json) {
    const ctx = new ConversationContext();
    if (json) {
      ctx.history = json.history || [];
      ctx.lastTimeRange = json.lastTimeRange || null;
      ctx.lastUser = json.lastUser || null;
      ctx.lastAgent = json.lastAgent || null;
      ctx.lastIntent = json.lastIntent ? INTENTS.find(i => i.id === json.lastIntent) : null;
    }
    return ctx;
  }
}

export default { parseQuery, generateElasticsearchQuery, formatResponse, ConversationContext };
