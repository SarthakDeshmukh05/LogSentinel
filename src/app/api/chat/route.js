// API Route: /api/chat — Conversational SIEM Assistant powered by Groq LLM
export const dynamic = 'force-dynamic';

const WAZUH_URL = process.env.WAZUH_URL || 'https://ad4f-103-97-164-99.ngrok-free.app';
const WAZUH_USER = process.env.WAZUH_USER || 'admin';
const WAZUH_PASS = process.env.WAZUH_PASS || 'SecretPassword';

const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const GROQ_MODEL = 'openai/gpt-oss-120b';
const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

// In-memory sessions
const sessions = new Map();

// ============ ELASTICSEARCH CONNECTOR ============
async function queryElasticsearch(body) {
  try {
    const res = await fetch(`${WAZUH_URL}/wazuh-alerts-*/_search`, {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${WAZUH_USER}:${WAZUH_PASS}`).toString('base64'),
        'Content-Type': 'application/json',
        'ngrok-skip-browser-warning': 'true',
      },
      cache: 'no-store',
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errText = await res.text();
      return { error: true, status: res.status, message: errText.substring(0, 300) };
    }
    return await res.json();
  } catch (err) {
    return { error: true, message: err.message };
  }
}

// Fetch index mapping (cached)
let cachedMapping = null;
let mappingFetchedAt = 0;

async function getIndexMapping() {
  if (cachedMapping && Date.now() - mappingFetchedAt < 600000) return cachedMapping;
  try {
    const res = await fetch(`${WAZUH_URL}/wazuh-alerts-*/_mapping?pretty`, {
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${WAZUH_USER}:${WAZUH_PASS}`).toString('base64'),
        'ngrok-skip-browser-warning': 'true',
      },
      cache: 'no-store',
    });
    if (res.ok) {
      const data = await res.json();
      // Extract field names from the first index mapping
      const indexName = Object.keys(data)[0];
      const props = data[indexName]?.mappings?.properties || {};
      cachedMapping = extractFieldPaths(props, '', 0);
      mappingFetchedAt = Date.now();
      return cachedMapping;
    }
  } catch (e) {
    console.error('Mapping fetch failed:', e.message);
  }
  return getDefaultMapping();
}

function extractFieldPaths(properties, prefix, depth) {
  if (depth > 4) return [];
  const fields = [];
  for (const [key, val] of Object.entries(properties)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (val.type) {
      fields.push({ field: path, type: val.type });
    }
    if (val.properties) {
      fields.push(...extractFieldPaths(val.properties, path, depth + 1));
    }
  }
  return fields;
}

function getDefaultMapping() {
  return [
    { field: '@timestamp', type: 'date' },
    { field: 'rule.level', type: 'integer' },
    { field: 'rule.id', type: 'keyword' },
    { field: 'rule.description', type: 'text' },
    { field: 'rule.groups', type: 'keyword' },
    { field: 'rule.firedtimes', type: 'integer' },
    { field: 'rule.pci_dss', type: 'keyword' },
    { field: 'rule.gdpr', type: 'keyword' },
    { field: 'rule.hipaa', type: 'keyword' },
    { field: 'rule.nist_800_53', type: 'keyword' },
    { field: 'rule.tsc', type: 'keyword' },
    { field: 'rule.mitre.id', type: 'keyword' },
    { field: 'rule.mitre.tactic', type: 'keyword' },
    { field: 'rule.mitre.technique', type: 'keyword' },
    { field: 'agent.id', type: 'keyword' },
    { field: 'agent.name', type: 'keyword' },
    { field: 'agent.ip', type: 'keyword' },
    { field: 'data.sca.check.title', type: 'text' },
    { field: 'data.sca.check.result', type: 'keyword' },
    { field: 'data.sca.check.remediation', type: 'text' },
    { field: 'data.sca.check.description', type: 'text' },
    { field: 'data.sca.check.compliance.cis', type: 'keyword' },
    { field: 'data.sca.policy', type: 'text' },
    { field: 'data.sca.type', type: 'keyword' },
    { field: 'data.srcip', type: 'keyword' },
    { field: 'data.dstip', type: 'keyword' },
    { field: 'data.srcuser', type: 'keyword' },
    { field: 'data.dstuser', type: 'keyword' },
    { field: 'decoder.name', type: 'keyword' },
    { field: 'location', type: 'keyword' },
  ];
}

// Fetch a sample document to show the LLM actual data
async function getSampleDocument() {
  const result = await queryElasticsearch({
    size: 2,
    sort: [{ '@timestamp': 'desc' }],
  });
  if (result.error || !result.hits?.hits?.length) return null;
  return result.hits.hits.map(h => h._source);
}

// ============ GROQ LLM ============
async function callGroq(messages) {
  try {
    const res = await fetch(GROQ_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        messages,
        temperature: 0.1,
        max_tokens: 2048,
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error(`Groq API error ${res.status}:`, errText.substring(0, 500));
      return null;
    }

    const data = await res.json();
    return data.choices?.[0]?.message?.content || null;
  } catch (err) {
    console.error('Groq API error:', err.message);
    return null;
  }
}

// ============ SYSTEM PROMPT BUILDER ============
function buildSystemPrompt(fieldSummary, sampleDoc) {
  return `You are a SIEM security assistant for a Wazuh/Elasticsearch deployment. Your job is to translate user questions about security data into Elasticsearch DSL queries and then explain the results in clear language.

## ELASTICSEARCH INDEX
- Index pattern: \`wazuh-alerts-*\`
- Available fields (top-level paths with types):
${fieldSummary}

## SAMPLE DOCUMENT
Here is a real document from the index so you understand the data structure:
\`\`\`json
${JSON.stringify(sampleDoc, null, 2)?.substring(0, 3000)}
\`\`\`

## YOUR RESPONSIBILITIES
1. Parse the user's natural language question
2. Generate a valid Elasticsearch DSL query (JSON) that answers it
3. Return your response in this exact JSON format:

\`\`\`json
{
  "elasticsearch_query": { ... valid ES DSL query ... },
  "explanation": "Brief explanation of what this query does",
  "intent": "one of: search, count, aggregate, report, compliance, help",
  "chart_config": {
    "type": "pie | bar",
    "title": "Chart Title",
    "agg_name": "the explicit key name of the top-level aggregation in your elasticsearch_query"
  }
}
\`\`\`

## QUERY RULES
- Always include a time range filter on \`@timestamp\` unless the user specifies "all time"
- Default time range is last 24 hours: \`{"range": {"@timestamp": {"gte": "now-24h"}}}\`
- For text fields, use \`match\` or \`match_phrase\`. For keyword fields, use \`term\` or \`terms\`
- Include \`size: 25\` for search queries, \`size: 0\` for pure aggregations
- Sort by \`@timestamp\` descending by default
- For "how many" or count questions, use aggregations with \`size: 0\`
- For "top N" questions, use \`terms\` aggregation with the specified size
- For compliance/SCA queries, search in \`data.sca.check.*\` fields and \`data.sca.type\`
- The field \`data.sca.check.result\` has values: "passed", "failed", "not applicable"
- The field \`rule.level\` is an integer (0-15), higher = more severe
- **CHARTING**: If the user explicitly asks for a pie chart, bar chart, or visual representation, you MUST include \`chart_config\`. Do NOT include \`chart_config\` for standard search queries.
- For report/summary requests or "overall posture" queries, you MUST include multiple robust aggregations in your query (e.g., aggregate by rule.level, by agent.name, and by rule.description) to provide a comprehensive dataset instead of just a basic search.

## IMPORTANT
- Return ONLY valid JSON. No markdown, no code fences, no extra text.
- If the user asks something you cannot query, return a helpful message in the explanation field with an empty query.`;
}

// ============ RESULT ANALYSIS PROMPT ============
function buildAnalysisPrompt(userQuestion, esResults, queryExplanation) {
  const totalHits = esResults?.hits?.total?.value || 0;
  const hits = (esResults?.hits?.hits || []).slice(0, 10);
  const aggs = esResults?.aggregations || {};

  const hitsPreview = hits.map(h => {
    const s = h._source || {};
    return {
      timestamp: s['@timestamp'],
      agent: s.agent?.name,
      rule_level: s.rule?.level,
      rule_desc: s.rule?.description?.substring(0, 120),
      rule_groups: s.rule?.groups,
      sca_result: s.data?.sca?.check?.result,
      sca_title: s.data?.sca?.check?.title?.substring(0, 100),
      mitre: s.rule?.mitre?.id,
    };
  });

  return `The user asked: "${userQuestion}"

Query explanation: ${queryExplanation}

## RESULTS
Total hits: ${totalHits}

### Top ${hits.length} hits:
${JSON.stringify(hitsPreview, null, 2)}

### Aggregations:
${JSON.stringify(aggs, null, 2)?.substring(0, 3000)}

## YOUR TASK
Provide a clear, professional security analyst response using markdown formatting:
- Use **bold** for emphasis.
- **MANDATORY**: If formatting data as a table, you MUST use standard GitHub Flavored Markdown (GFM) tables. You MUST include the header separator row (e.g., \`|---|---|---|\`) immediately below the header row, otherwise the UI will break.
- Include security recommendations when relevant.
- Note any concerning patterns.
- If results are 0, suggest alternative queries or explain why.
- Keep it concise but informative (max ~300 words).
- **MANDATORY**: Do NOT output raw JSON blocks or Elasticsearch queries in your narrative response. Keep it purely conversational.
- Start with a status emoji (🔍 for search, 📊 for stats, ✅ for good news, ⚠️ for warnings, 🔴 for critical).`;
}

// ============ MAIN HANDLER ============
export async function POST(request) {
  try {
    const body = await request.json();
    const userMessage = body.message?.trim();
    const sessionId = body.sessionId || 'default';

    if (!userMessage) {
      return jsonResponse({ error: 'Message is required' }, 400);
    }

    // Get or create session
    if (!sessions.has(sessionId)) {
      sessions.set(sessionId, { history: [], turnCount: 0 });
    }
    const session = sessions.get(sessionId);

    // Handle "help" locally
    if (userMessage.toLowerCase() === 'help') {
      return jsonResponse({
        message: buildHelpMessage(),
        data: { hits: [], aggregations: {}, charts: [] },
        totalHits: 0,
        meta: { intent: 'help', queryExecuted: false },
      });
    }

    // Step 1: Get index mapping + sample doc (parallel)
    const [mapping, sampleDocs] = await Promise.all([
      getIndexMapping(),
      session.turnCount === 0 ? getSampleDocument() : Promise.resolve(null),
    ]);

    const fieldSummary = (mapping || [])
      .slice(0, 60)
      .map(f => `  - \`${f.field}\` (${f.type})`)
      .join('\n');

    const sampleDoc = sampleDocs?.[0] || session.cachedSample || null;
    if (sampleDoc) session.cachedSample = sampleDoc;

    // Step 2: Build conversation for Groq
    const systemPrompt = buildSystemPrompt(fieldSummary, sampleDoc);

    const groqMessages = [
      { role: 'system', content: systemPrompt },
    ];

    // Add conversation history (last 6 turns)
    for (const turn of session.history.slice(-6)) {
      groqMessages.push({ role: 'user', content: turn.userMessage });
      if (turn.assistantSummary) {
        groqMessages.push({ role: 'assistant', content: turn.assistantSummary });
      }
    }

    groqMessages.push({ role: 'user', content: userMessage });

    // Step 3: Call Groq to generate ES query
    console.log(`[SIEM Chat] Calling Groq LLM for: "${userMessage.substring(0, 80)}"`);
    const llmResponse = await callGroq(groqMessages);

    if (!llmResponse) {
      return jsonResponse({
        message: '⚠️ **LLM Unavailable**: Could not reach the AI backend. Please try again.',
        data: { hits: [], aggregations: {}, charts: [] },
        totalHits: 0,
        meta: { intent: 'error', queryExecuted: false },
      });
    }

    // Step 4: Parse the LLM response
    let parsed;
    try {
      // Clean potential markdown wrapping
      let cleaned = llmResponse.trim();
      if (cleaned.startsWith('```')) {
        cleaned = cleaned.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '');
      }
      parsed = JSON.parse(cleaned);
    } catch (e) {
      console.error('LLM response parse error:', e.message, '\nRaw:', llmResponse.substring(0, 500));
      // Try to extract JSON from the response
      const jsonMatch = llmResponse.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try { parsed = JSON.parse(jsonMatch[0]); } catch (e2) {
          return jsonResponse({
            message: `⚠️ **Parse Error**: The AI generated an invalid response. Retrying may help.\n\n_Raw snippet:_ \`${llmResponse.substring(0, 200)}\``,
            data: { hits: [], aggregations: {}, charts: [] },
            totalHits: 0,
            meta: { intent: 'error', queryExecuted: false },
          });
        }
      }
    }

    if (!parsed) {
      return jsonResponse({
        message: '⚠️ Could not parse the AI response. Please rephrase your question.',
        data: { hits: [], aggregations: {}, charts: [] },
        totalHits: 0,
        meta: { intent: 'error', queryExecuted: false },
      });
    }

    const esQuery = parsed.elasticsearch_query;
    const queryExplanation = parsed.explanation || '';
    const intent = parsed.intent || 'search';

    // Step 5: Execute query against live Wazuh
    let esResults = null;
    let formattedHits = [];
    let totalHits = 0;

    if (esQuery && Object.keys(esQuery).length > 0) {
      console.log(`[SIEM Chat] Executing ES query:`, JSON.stringify(esQuery).substring(0, 300));
      esResults = await queryElasticsearch(esQuery);

      if (esResults.error) {
        return jsonResponse({
          message: `⚠️ **Elasticsearch Error**: ${esResults.message || 'Query failed'}.\n\n_Query explanation:_ ${queryExplanation}`,
          data: { hits: [], aggregations: {}, charts: [] },
          totalHits: 0,
          meta: { intent, queryExecuted: false },
          debug: { elasticsearch_query: esQuery, error: esResults.message },
        });
      }

      totalHits = esResults?.hits?.total?.value || 0;
      formattedHits = (esResults?.hits?.hits || []).slice(0, 20).map(hit => {
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
    }

    // Step 6: Call Groq to analyze results and generate narrative
    const analysisPrompt = buildAnalysisPrompt(userMessage, esResults, queryExplanation);
    const analysisMessages = [
      { role: 'system', content: 'You are a senior cybersecurity analyst. Provide concise, actionable security analysis. Use markdown formatting with **bold**, tables, and emojis. Keep responses under 300 words.' },
      { role: 'user', content: analysisPrompt },
    ];

    const narrative = await callGroq(analysisMessages);

    // Step 7: Format aggregations
    const formattedAggs = {};
    const rawAggs = esResults?.aggregations || {};
    for (const [key, agg] of Object.entries(rawAggs)) {
      if (agg.buckets) {
        formattedAggs[key] = agg.buckets.map(b => ({
          key: b.key_as_string || b.key,
          count: b.doc_count,
        }));
      }
    }

    // Step 8: Update session history
    session.history.push({
      userMessage,
      assistantSummary: `[Intent: ${intent}] [Hits: ${totalHits}] ${queryExplanation}`,
      esQuery,
      timestamp: Date.now(),
    });
    session.turnCount++;
    if (session.history.length > 20) session.history.shift();

    // Step 9: Return response
    return jsonResponse({
      message: narrative || parsed.explanation || 'Analysis complete.',
      data: {
        hits: formattedHits,
        aggregations: formattedAggs,
        chart_config: parsed.chart_config || null,
      },
      totalHits,
      meta: {
        intent,
        queryExecuted: !esResults?.error,
        llm_query_explanation: queryExplanation,
        entities: {},
      },
      debug: {
        elasticsearch_query: esQuery,
        parsed_intent: intent,
      },
      conversationHistory: session.history.slice(-5).map(h => ({
        userQuery: h.userMessage,
        intent: h.assistantSummary?.match(/\[Intent: (\w+)\]/)?.[1],
        hits: parseInt(h.assistantSummary?.match(/\[Hits: (\d+)\]/)?.[1] || '0'),
      })),
    });
  } catch (error) {
    console.error('Chat API error:', error);
    return jsonResponse({
      message: `❌ **Internal Error**: ${error.message}. Please try again.`,
      data: { hits: [], aggregations: {}, charts: [] },
      totalHits: 0,
    });
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function buildHelpMessage() {
  return `## 🤖 SIEM Assistant — Powered by AI

I understand natural language and translate your questions into Elasticsearch queries against your live Wazuh data.

**Investigation Queries:**
- "Show all SCA compliance failures"
- "What security checks failed on agent wazuh.manager?"
- "Find events with rule level above 10"
- "Show alerts related to password policy"
- "What MITRE techniques were detected this week?"

**Compliance & SCA:**
- "Show all failed CIS benchmark checks"
- "What is the compliance pass rate?"
- "Find remediation steps for failed checks"
- "Show SCA results for file permissions"

**Analytics & Reports:**
- "How many alerts by severity level?"
- "Top 10 most triggered rules"
- "Generate a security summary for today"
- "Show event distribution by agent"
- "What are the most common rule groups?"

**Follow-up Queries:**
After any query, you can refine results naturally:
- "Now filter only critical ones"
- "What about last week instead?"
- "Show me more details on the first result"

💡 **Tip:** I maintain context between messages, so follow-up questions work naturally!`;
}
