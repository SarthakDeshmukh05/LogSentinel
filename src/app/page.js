'use client';

import { useState, useEffect, useCallback, useRef } from 'react';

// ============ SEVERITY HELPERS ============
function getSeverityIcon(level) {
  const icons = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };
  return icons[level] || '⚪';
}

function getSeverityColor(level) {
  const colors = { CRITICAL: '#ff1744', HIGH: '#ff6d00', MEDIUM: '#ffc400', LOW: '#00e676' };
  return colors[level] || '#64748b';
}

// ============ RISK SCORE RING ============
function RiskScoreRing({ score, level }) {
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score * circumference);
  const color = getSeverityColor(level);

  return (
    <div className="risk-score-ring">
      <svg viewBox="0 0 80 80">
        <circle className="bg-circle" cx="40" cy="40" r={radius} />
        <circle
          className="progress-circle"
          cx="40" cy="40" r={radius}
          stroke={color}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="risk-score-value" style={{ color }}>
        {Math.round(score * 100)}%
      </div>
    </div>
  );
}

// ============ DONUT CHART ============
function DonutChart({ distribution, total }) {
  const segments = [
    { key: 'CRITICAL', color: '#ff1744', count: distribution.CRITICAL || 0 },
    { key: 'HIGH', color: '#ff6d00', count: distribution.HIGH || 0 },
    { key: 'MEDIUM', color: '#ffc400', count: distribution.MEDIUM || 0 },
    { key: 'LOW', color: '#00e676', count: distribution.LOW || 0 },
  ];

  const totalAlerts = segments.reduce((sum, s) => sum + s.count, 0);
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="chart-container">
      <div className="donut-chart">
        <svg viewBox="0 0 160 160">
          {segments.map((seg) => {
            const segLen = totalAlerts > 0 ? (seg.count / totalAlerts) * circumference : 0;
            const el = (
              <circle
                key={seg.key}
                cx="80" cy="80" r={radius}
                fill="none"
                stroke={seg.color}
                strokeWidth="14"
                strokeDasharray={`${segLen} ${circumference - segLen}`}
                strokeDashoffset={-offset}
                strokeLinecap="round"
                opacity="0.85"
              />
            );
            offset += segLen;
            return el;
          })}
        </svg>
        <div className="donut-center">
          <div className="donut-center-value">{totalAlerts}</div>
          <div className="donut-center-label">Alerts</div>
        </div>
      </div>
      <div className="chart-legend">
        {segments.map(seg => (
          <div className="legend-item" key={seg.key}>
            <span className="legend-dot" style={{ background: seg.color }} />
            {seg.key} <span className="legend-count">{seg.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============ ALERT DETAIL MODAL ============
function AlertModal({ alert, onClose }) {
  if (!alert) return null;

  const explanation = alert.explanation || {};
  const severity = alert.severity || {};
  const ml = alert.ml_detection || {};
  const features = alert.features || {};

  const handleGenerateReport = () => {
    const reportData = {
      detection_date: new Date().toISOString().split('T')[0],
      detection_time: new Date().toLocaleTimeString('en-US', { timeZoneName: 'short' }),
      occurrence_date: new Date(alert.timestamp).toISOString().split('T')[0],
      occurrence_time: new Date(alert.timestamp).toLocaleTimeString('en-US', { timeZoneName: 'short' }),
      source_ip: alert.ip_address || 'Unknown',
      source_location: alert.geo_country ? `${alert.geo_city || 'Unknown'}, ${alert.geo_country}` : 'Unknown',
      source_port: alert.raw_data?.src_port || 'Unknown',
      dest_ip: alert.raw_data?.dest_ip || alert.agent_ip || 'Local',
      dest_system_id: alert.agent_name || 'System',
      dest_port: alert.raw_data?.dest_port || 'Unknown',
      summary: alert.explanation?.primary || alert.rule_description,
      systems_affected: alert.agent_name,
      data_risk: alert.severity?.level + ' Risk Detected - ' + (alert.rule_description || ''),
      downtime: 'Pending Investigation'
    };
    
    try {
      const existing = JSON.parse(localStorage.getItem('logsentinel_reports') || '{}');
      existing[alert.event_id] = reportData;
      localStorage.setItem('logsentinel_reports', JSON.stringify(existing));
    } catch(e) {}
    
    window.open(`/report?event_id=${alert.event_id}`, '_blank');
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <div className="modal-title">
              {getSeverityIcon(severity.level)} Alert Detail — {alert.event_id}
            </div>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: '0.8rem' }} onClick={handleGenerateReport}>
              📄 Generate IR Report
            </button>
            <button className="modal-close" onClick={onClose}>✕</button>
          </div>
        </div>
        <div className="modal-body">
          {/* Severity */}
          <div className="modal-section">
            <div className="modal-section-title">Risk Assessment</div>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: 12 }}>
              <span className={`severity-badge ${severity.level}`}>
                {getSeverityIcon(severity.level)} {severity.level}
              </span>
              <span className="mono text-secondary">Score: {((severity.score || 0) * 100).toFixed(1)}%</span>
            </div>
            {severity.components && (
              <div className="feature-importance-bars">
                {Object.entries(severity.components).map(([key, val]) => (
                  <div className="feature-bar" key={key}>
                    <span className="feature-bar-name">{key.replace(/_/g, ' ')}</span>
                    <div className="feature-bar-track">
                      <div className="feature-bar-fill" style={{ width: `${Math.min(100, val * 100)}%` }} />
                    </div>
                    <span className="feature-bar-value">{(val * 100).toFixed(0)}%</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Explanation */}
          {explanation.primary && (
            <div className="modal-section">
              <div className="modal-section-title">Explanation</div>
              <div className="modal-explanation" dangerouslySetInnerHTML={{
                __html: explanation.primary
                  .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                  .replace(/`(.*?)`/g, '<code style="background:rgba(99,102,241,0.2);padding:2px 6px;border-radius:4px;font-size:0.82rem">$1</code>')
              }} />
            </div>
          )}

          {/* Auto-Remediation */}
          {explanation.remediation_code && (
            <div className="modal-section">
              <div className="modal-section-title" style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>🛡️ Auto-Remediation Commands</span>
                <button 
                  className="btn btn-secondary" 
                  style={{ padding: '2px 8px', fontSize: '0.7rem' }}
                  onClick={() => navigator.clipboard.writeText(explanation.remediation_code)}
                >
                  Copy All
                </button>
              </div>
              <pre style={{ 
                background: 'var(--bg-secondary)', 
                padding: '12px', 
                borderRadius: '8px', 
                border: '1px solid var(--border-subtle)',
                overflowX: 'auto',
                fontSize: '0.85rem',
                color: 'var(--text-primary)',
                lineHeight: 1.5,
                margin: 0
              }}>
                <code style={{ fontFamily: 'var(--font-mono)' }}>
                  {explanation.remediation_code}
                </code>
              </pre>
            </div>
          )}

          {/* Interactive Threat Graph */}
          {(alert.severity?.level === 'CRITICAL' || alert.severity?.level === 'HIGH') && (
            <div className="modal-section">
              <div className="modal-section-title">Attack Vector Graph</div>
              <div style={{ 
                background: 'var(--bg-elevated)', borderRadius: 8, padding: 24, display: 'flex', 
                alignItems: 'center', justifyContent: 'center', border: '1px solid var(--border-subtle)',
                overflowX: 'auto', position: 'relative'
              }}>
                <svg width="600" height="120" style={{ minWidth: 600 }}>
                  <defs>
                    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                      <polygon points="0 0, 10 3.5, 0 7" fill="var(--critical)" />
                    </marker>
                    <marker id="arrowhead-gray" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                      <polygon points="0 0, 10 3.5, 0 7" fill="var(--text-muted)" />
                    </marker>
                  </defs>
                  
                  {/* Lines */}
                  {alert.ip_address && (
                    <line x1="85" y1="50" x2="265" y2="50" stroke={alert.ip_address !== 'unknown' ? "var(--critical)" : "var(--border-subtle)"} strokeWidth="2" strokeDasharray="5,5" markerEnd="url(#arrowhead)" />
                  )}
                  <line x1="335" y1="50" x2="515" y2="50" stroke="var(--critical)" strokeWidth="2" markerEnd="url(#arrowhead)" />

                  {/* Nodes */}
                  <g transform="translate(50, 50)">
                    <circle cx="0" cy="0" r="35" fill="var(--bg-primary)" stroke="var(--text-muted)" strokeWidth="2" />
                    <text x="0" y="-5" textAnchor="middle" fill="var(--text-primary)" fontSize="12" fontWeight="600">Attacker IP</text>
                    <text x="0" y="15" textAnchor="middle" fill="var(--text-secondary)" fontSize="10">{alert.ip_address || 'Unknown'}</text>
                  </g>

                  <g transform="translate(300, 50)">
                    <circle cx="0" cy="0" r="35" fill="var(--bg-primary)" stroke="var(--high)" strokeWidth="2" />
                    <text x="0" y="-5" textAnchor="middle" fill="var(--text-primary)" fontSize="12" fontWeight="600">User Acc</text>
                    <text x="0" y="15" textAnchor="middle" fill="var(--text-secondary)" fontSize="10">{alert.user_id && alert.user_id !== 'unknown' ? alert.user_id : 'System Auth'}</text>
                  </g>

                  <g transform="translate(550, 50)">
                    <circle cx="0" cy="0" r="35" fill="var(--critical-bg)" stroke="var(--critical)" strokeWidth="2" />
                    <text x="0" y="-5" textAnchor="middle" fill="var(--text-primary)" fontSize="12" fontWeight="600">Target</text>
                    <text x="0" y="15" textAnchor="middle" fill="var(--text-secondary)" fontSize="10">{alert.agent_name || 'Agent'}</text>
                  </g>
                </svg>
              </div>
            </div>
          )}

          {/* Event Meta */}
          <div className="modal-section">
            <div className="modal-section-title">Event Details</div>
            <div className="modal-meta-grid">
              <div className="modal-meta-item">
                <div className="modal-meta-label">Timestamp</div>
                <div className="modal-meta-value mono">{new Date(alert.timestamp).toLocaleString()}</div>
              </div>
              <div className="modal-meta-item">
                <div className="modal-meta-label">User</div>
                <div className="modal-meta-value">{alert.user_id}</div>
              </div>
              <div className="modal-meta-item">
                <div className="modal-meta-label">IP Address</div>
                <div className="modal-meta-value mono">{alert.ip_address}</div>
              </div>
              <div className="modal-meta-item">
                <div className="modal-meta-label">Location</div>
                <div className="modal-meta-value">{alert.geo_city}, {alert.geo_country}</div>
              </div>
              <div className="modal-meta-item">
                <div className="modal-meta-label">Event Type</div>
                <div className="modal-meta-value">{alert.event_type}</div>
              </div>
              <div className="modal-meta-item">
                <div className="modal-meta-label">Source</div>
                <div className="modal-meta-value">{alert.source}</div>
              </div>
            </div>
          </div>

          {/* RCA Timeline */}
          {alert.rca_chain?.length > 0 && (
            <div className="modal-section">
              <div className="modal-section-title">Root Cause Analysis (RCA) Timeline</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', position: 'relative', paddingLeft: '16px', borderLeft: '2px dashed var(--border-active)' }}>
                {alert.rca_chain.map((c, i) => (
                  <div key={i} style={{ position: 'relative' }}>
                    <div style={{ position: 'absolute', left: '-23px', top: '4px', background: 'var(--bg-elevated)', border: '2px solid var(--border-active)', width: 12, height: 12, borderRadius: '50%' }} />
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{new Date(c.timestamp).toLocaleTimeString()}</div>
                    <div style={{ fontWeight: 600 }}>{c.event_type} <span style={{ fontWeight: 400, color: 'var(--text-muted)' }}>on {c.agent}</span></div>
                    <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{c.rule}</div>
                  </div>
                ))}
                
                {/* Final step is the alert itself */}
                <div style={{ position: 'relative', marginTop: 8 }}>
                  <div style={{ position: 'absolute', left: '-23px', top: '4px', background: 'var(--critical)', border: '2px solid var(--critical)', width: 12, height: 12, borderRadius: '50%', boxShadow: '0 0 8px var(--critical)' }} />
                  <div style={{ fontSize: '0.8rem', color: 'var(--critical)' }}>{new Date(alert.timestamp).toLocaleTimeString()} (Alert)</div>
                  <div style={{ fontWeight: 600, color: 'white' }}>{alert.event_type}</div>
                  <div style={{ fontSize: '0.82rem', color: 'var(--critical)' }}>{alert.rule_description}</div>
                </div>
              </div>
            </div>
          )}

          {/* MITRE ATT&CK */}
          {(alert.mitre_tactic_details?.length > 0 || alert.mitre_technique_details?.length > 0) && (
            <div className="modal-section">
              <div className="modal-section-title">MITRE ATT&CK Mapping</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {alert.mitre_tactic_details?.map(t => (
                  <div key={t.id} className="compliance-check-item" style={{ borderLeftColor: 'var(--accent-cyan)' }}>
                    <div className="check-title">{t.id}: {t.name}</div>
                    <div className="check-remediation">{t.description}</div>
                  </div>
                ))}
                {alert.mitre_technique_details?.map(t => (
                  <div key={t.id} className="compliance-check-item" style={{ borderLeftColor: 'var(--accent-primary)' }}>
                    <div className="check-title">{t.id}: {t.name}</div>
                    <div className="check-remediation">{t.description}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ML Feature Importance */}
          {ml.feature_importances?.length > 0 && (
            <div className="modal-section">
              <div className="modal-section-title">ML Feature Attribution</div>
              <div className="feature-importance-bars">
                {ml.feature_importances.map((f, i) => (
                  <div className="feature-bar" key={i}>
                    <span className="feature-bar-name">{f.feature.replace(/_/g, ' ')}</span>
                    <div className="feature-bar-track">
                      <div className="feature-bar-fill" style={{ width: `${Math.min(100, f.importance * 500)}%` }} />
                    </div>
                    <span className="feature-bar-value">{(f.importance * 100).toFixed(1)}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Rules Matched */}
          {alert.rule_matches?.length > 0 && (
            <div className="modal-section">
              <div className="modal-section-title">Rules Triggered</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {alert.rule_matches.map((r, i) => (
                  <div key={i} className="compliance-check-item" style={{ borderLeftColor: getSeverityColor(r.severity) }}>
                    <div className="check-title">{r.rule_id}: {r.rule_name}</div>
                    <div className="check-remediation">{r.description}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation for SCA */}
          {alert.raw_data?.sca_remediation && (
            <div className="modal-section">
              <div className="modal-section-title">Remediation</div>
              <div className="modal-explanation" style={{ borderLeftColor: 'var(--low)' }}>
                {alert.raw_data.sca_remediation}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============ GENERATIVE AI CHART ============
function GenerativeChart({ config, aggregations }) {
  if (!config || !aggregations) return null;
  const dataMap = aggregations[config.agg_name];
  if (!dataMap || !Array.isArray(dataMap) || dataMap.length === 0) return null;

  const total = dataMap.reduce((sum, item) => sum + item.count, 0);
  const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#14b8a6'];

  if (config.type === 'bar') {
    const maxVal = Math.max(...dataMap.map(d => d.count));
    return (
      <div className="generated-chart-container" style={{ background: 'var(--bg-elevated)', padding: 16, borderRadius: 8, marginTop: 12, border: '1px solid var(--border-subtle)' }}>
        <div style={{ fontSize: '0.85rem', fontWeight: 'bold', marginBottom: 12, color: 'var(--text-secondary)' }}>📊 {config.title || 'Bar Chart'}</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {dataMap.slice(0, 10).map((item, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ width: 120, fontSize: '0.75rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={item.key}>{item.key}</div>
              <div style={{ flex: 1, height: 16, background: 'rgba(0,0,0,0.05)', borderRadius: 4, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${(item.count / maxVal) * 100}%`, background: colors[i % colors.length], borderRadius: 4 }} />
              </div>
              <div style={{ width: 40, fontSize: '0.75rem', fontWeight: 'bold', textAlign: 'right' }}>{item.count}</div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (config.type === 'pie') {
    let currentOffset = 0;
    const radius = 50;
    const circumference = 2 * Math.PI * radius;

    return (
      <div className="generated-chart-container" style={{ background: 'var(--bg-elevated)', padding: 16, borderRadius: 8, marginTop: 12, border: '1px solid var(--border-subtle)' }}>
        <div style={{ fontSize: '0.85rem', fontWeight: 'bold', marginBottom: 16, color: 'var(--text-secondary)' }}>🍩 {config.title || 'Distribution'}</div>
        <div style={{ display: 'flex', gap: 32, alignItems: 'center' }}>
          <svg viewBox="0 0 120 120" style={{ width: 120, height: 120, transform: 'rotate(-90deg)' }}>
            {dataMap.slice(0, 8).map((item, i) => {
              const portion = item.count / total;
              if (portion === 0) return null;
              const strokeLength = portion * circumference;
              const offset = -currentOffset;
              currentOffset += strokeLength;
              return (
                <circle
                  key={i}
                  cx="60" cy="60" r={radius}
                  fill="transparent"
                  stroke={colors[i % colors.length]}
                  strokeWidth="20"
                  strokeDasharray={`${strokeLength} ${circumference}`}
                  strokeDashoffset={offset}
                />
              );
            })}
          </svg>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
            {dataMap.slice(0, 8).map((item, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.75rem' }}>
                <span style={{ width: 10, height: 10, background: colors[i % colors.length], borderRadius: '50%' }} />
                <span style={{ flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={item.key}>{item.key}</span>
                <span style={{ fontWeight: 'bold', minWidth: '30px', textAlign: 'right' }}>{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return null;
}

// ============ CUSTOM MARKDOWN PARSER ============
function formatChatMessage(text) {
  if (!text) return '';
  let html = text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/`(.*?)`/g, '<code>$1</code>')
    .replace(/^### (.+)$/gm, '<h3 style="margin:12px 0 6px;font-size:1.1rem;color:var(--text-primary)">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 style="margin:14px 0 8px;font-size:1.2rem;color:var(--accent-cyan);border-bottom:1px solid var(--border-subtle);padding-bottom:4px">$1</h2>')
    .replace(/^# (.+)$/gm, '<h1 style="margin:16px 0 8px;font-size:1.4rem;color:var(--critical)">$1</h1>')
    .replace(/\n- /g, '<br/>• ')
    .replace(/\n(\d+)\. /g, '<br/>$1. ');

  // Parse Markdown Tables correctly into <table> elements
  const lines = html.split('\n');
  let inTable = false;
  const newLines = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith('|') && line.endsWith('|')) {
      const cells = line.split('|').filter((_, idx, arr) => idx > 0 && idx < arr.length - 1).map(c => c.trim());
      if (cells.every(c => /^[-:]+$/.test(c))) {
        continue; // Skip the markdown separator row
      }
      if (!inTable) {
        inTable = true;
        newLines.push('<div style="overflow-x:auto;margin:12px 0;"><table style="width:100%;border-collapse:collapse;font-size:0.8rem;text-align:left;"><tbody>');
        // First line is header
        newLines.push('<tr style="background:var(--bg-document);border-bottom:2px solid var(--border-active)">' + cells.map(c => `<th style="padding:6px 12px;font-weight:bold">${c}</th>`).join('') + '</tr>');
      } else {
        newLines.push('<tr style="border-bottom:1px solid var(--border-subtle)">' + cells.map(c => `<td style="padding:6px 12px">${c}</td>`).join('') + '</tr>');
      }
    } else {
      if (inTable) {
        inTable = false;
        newLines.push('</tbody></table></div>');
      }
      newLines.push(line);
    }
  }
  
  if (inTable) {
    newLines.push('</tbody></table></div>');
  }

  return newLines.join('<br/>').replace(/<br\/><div style="overflow-x:auto;/g, '<div style="overflow-x:auto;').replace(/<\/div><br\/>/g, '</div>');
}

// ============ SIEM CHAT WIDGET ============
function SIEMChat({ isOpen, onClose }) {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: '🤖 **SIEM Assistant Ready** — Powered by AI\n\nI translate your natural language questions into live Elasticsearch queries against your Wazuh SIEM data.\n\n- "Show all failed SCA compliance checks"\n- "What alerts have rule level above 10?"\n- "Generate a security report for today"\n- "Top 10 most triggered rules"\n\nType **help** for all available commands.',
      meta: null,
      data: null,
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [sessionId] = useState(() => 'session-' + Date.now());
  const [showDebug, setShowDebug] = useState(false);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    if (isOpen) inputRef.current?.focus();
  }, [isOpen]);

  const sendMessage = async () => {
    const text = input.trim();
    if (!text || isLoading) return;

    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: text }]);
    setIsLoading(true);

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, sessionId }),
      });
      const data = await res.json();
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.message || 'No response',
        meta: data.meta,
        data: data.data,
        debug: data.debug,
        totalHits: data.totalHits,
      }]);
    } catch (err) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `❌ **Error**: ${err.message}. Please try again.`,
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: '1.2rem' }}>🤖</span>
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>SIEM Assistant</div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Natural Language → Elasticsearch DSL</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            className="chat-header-btn"
            onClick={() => setShowDebug(!showDebug)}
            title="Toggle debug info"
          >
            {showDebug ? '🔍' : '🔎'}
          </button>
          <button className="chat-header-btn" onClick={onClose}>✕</button>
        </div>
      </div>

      <div className="chat-messages">
        {messages.map((msg, i) => (
          <div key={i} className={`chat-message ${msg.role}`}>
            <div
              className="chat-message-content"
              dangerouslySetInnerHTML={{ __html: formatChatMessage(msg.content) }}
            />

            {/* NLP Metadata */}
            {msg.meta && (
              <div className="chat-meta">
                {msg.meta.intent && (
                  <span className="chat-meta-tag">🧠 {msg.meta.intent}</span>
                )}
                {msg.totalHits !== undefined && (
                  <span className="chat-meta-tag">📊 {msg.totalHits} hits</span>
                )}
                {msg.meta.queryExecuted === false && (
                  <span className="chat-meta-tag" style={{ color: 'var(--medium)' }}>⚡ No query</span>
                )}
                {msg.meta.llm_query_explanation && (
                  <span className="chat-meta-tag" style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    🔍 {msg.meta.llm_query_explanation.substring(0, 80)}
                  </span>
                )}
              </div>
            )}

            {/* Hit Results Table */}
            {msg.data?.hits?.length > 0 && (
              <div className="chat-results">
                <div className="chat-results-header">Top Results ({msg.data.hits.length} shown)</div>
                <div className="chat-results-table-wrap">
                  <table className="chat-results-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Agent</th>
                        <th>Level</th>
                        <th>Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {msg.data.hits.slice(0, 8).map((hit, j) => (
                        <tr key={j}>
                          <td className="mono">{hit.timestamp ? new Date(hit.timestamp).toLocaleTimeString() : '-'}</td>
                          <td>{hit.agent}</td>
                          <td>
                            <span style={{
                              color: hit.rule_level >= 12 ? 'var(--critical)' :
                                hit.rule_level >= 8 ? 'var(--high)' :
                                  hit.rule_level >= 4 ? 'var(--medium)' : 'var(--low)',
                              fontWeight: 700,
                            }}>
                              {hit.rule_level}
                            </span>
                          </td>
                          <td>{hit.rule_description || hit.sca_title || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* GENERATIVE AI CHART */}
            {msg.data?.chart_config && msg.data?.aggregations && (
              <GenerativeChart config={msg.data.chart_config} aggregations={msg.data.aggregations} />
            )}

            {/* Debug: ES Query */}
            {showDebug && msg.debug?.elasticsearch_query && (
              <details className="chat-debug">
                <summary>Elasticsearch DSL Query</summary>
                <pre>{JSON.stringify(msg.debug.elasticsearch_query, null, 2)}</pre>
              </details>
            )}
          </div>
        ))}
        {isLoading && (
          <div className="chat-message assistant">
            <div className="chat-message-content" style={{ color: 'var(--text-muted)' }}>
              <span className="chat-typing">Querying SIEM</span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <div className="chat-input-area">
        <input
          ref={inputRef}
          className="chat-input"
          type="text"
          placeholder="Ask about your security data..."
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') sendMessage(); }}
          disabled={isLoading}
        />
        <button className="chat-send" onClick={sendMessage} disabled={isLoading || !input.trim()}>
          ➤
        </button>
      </div>
    </div>
  );
}

// ============ MAIN DASHBOARD ============
export default function Dashboard() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [showBriefing, setShowBriefing] = useState(false);
  const [showChat, setShowChat] = useState(false);
  
  // Settings States
  const [showSettings, setShowSettings] = useState(false);
  const [mlSensitivity, setMlSensitivity] = useState(0.08);

  const fetchReport = useCallback(async (customThreshold = null) => {
    setLoading(true);
    setError(null);
    let lastError = null;
    
    const targetThreshold = customThreshold !== null ? customThreshold : mlSensitivity;

    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ anomalyThreshold: targetThreshold })
        });
        if (!res.ok) {
          lastError = `HTTP ${res.status}`;
          if (attempt < 2) { await new Promise(r => setTimeout(r, 500)); continue; }
          throw new Error(lastError);
        }
        const data = await res.json();
        setReport(data);
        setLoading(false);
        return;
      } catch (err) {
        lastError = err.message;
        if (attempt < 2) { await new Promise(r => setTimeout(r, 500)); continue; }
      }
    }
    setError(lastError || 'Pipeline failed after retries');
    setLoading(false);
  }, []);

  const handleFileUpload = async (e) => {
    e.preventDefault();
    const file = e.dataTransfer ? e.dataTransfer.files[0] : e.target.files[0];
    if (!file) return;

    setLoading(true);
    setError(null);

    try {
      const { parseClientCSV } = await import('@/lib/clientCsvParser');
      const csvEventsClient = await parseClientCSV(file, 2000); // 2000 events to stay under 4MB limit

      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csvEventsClient, anomalyThreshold: mlSensitivity })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setReport(data);
    } catch (err) {
      setError(err.message || 'File upload parsing failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchReport(); }, [fetchReport]);

  if (loading) {
    return (
      <div className="app-container">
        <div className="loading-container">
          <div className="loading-spinner" />
          <div className="loading-text">Running Security Pipeline...</div>
          <div className="text-muted" style={{ fontSize: '0.8rem' }}>
            Analyzing logs • Engineering features • Detecting anomalies • Generating explanations
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="app-container">
        <div className="loading-container">
          <div style={{ fontSize: '2rem' }}>⚠️</div>
          <div style={{ color: 'var(--critical)', fontWeight: 700 }}>Pipeline Error</div>
          <div className="text-secondary">{error}</div>
          <button className="btn btn-primary" onClick={fetchReport}>Retry Analysis</button>
        </div>
      </div>
    );
  }

  if (!report) return null;

  const {
    metadata, risk_posture, severity_distribution, top_alerts,
    all_alerts, timeline, mitre_heatmap, attack_type_summary,
    compliance_summary, security_briefing
  } = report;

  const filteredAlerts = severityFilter === 'ALL'
    ? (all_alerts || [])
    : (all_alerts || []).filter(a => a.severity?.level === severityFilter);

  return (
    <div 
      className="app-container"
      onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); }}
      onDrop={(e) => {
        e.preventDefault();
        e.stopPropagation();
        handleFileUpload(e);
      }}
    >
      {/* HEADER */}
      <header className="header" id="dashboard-header">
        <div className="header-brand">
          <div className="header-logo">🛡️</div>
          <div>
            <div className="header-title">Log-Sentinel</div>
            <div className="header-subtitle">Explainable Security Pipeline</div>
          </div>
        </div>
        <div className="header-actions" style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <label style={{
            background: 'var(--bg-elevated)', border: '1px dashed var(--border-active)', 
            padding: '6px 12px', borderRadius: '4px', fontSize: '0.8rem', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent-cyan)'
          }}>
            <span>📂 Drop Wazuh CSV or Click to Upload</span>
            <input type="file" accept=".csv" style={{ display: 'none' }} onChange={handleFileUpload} />
          </label>

          <button 
            onClick={() => setShowSettings(true)}
            style={{ 
              background: 'transparent', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)',
              padding: '6px', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center'
            }}
            title="System Tuner"
          >
            ⚙️
          </button>

          <div className="header-status">
            <span className="status-dot" />
            Pipeline Active
          </div>
          {metadata?.wazuh_live && (
            <div className="header-status" style={{ background: 'rgba(34,211,238,0.1)', borderColor: 'rgba(34,211,238,0.3)', color: '#22d3ee' }}>
              <span className="status-dot" style={{ background: '#22d3ee' }} />
              Wazuh Live
            </div>
          )}
          <button className="btn" onClick={() => setShowBriefing(!showBriefing)}>
            📄 {showBriefing ? 'Dashboard' : 'Briefing'}
          </button>
          <button className="btn" onClick={() => window.open('/voice', '_blank')}>
            🎙️ Voice AI
          </button>
          <button className="btn btn-primary" onClick={fetchReport}>
            🔄 Re-Analyze
          </button>
        </div>
      </header>

      {/* SECURITY BRIEFING VIEW */}
      {showBriefing && (
        <div className="section-card" style={{ marginBottom: 24 }}>
          <div className="section-header">
            <div className="section-title">📄 Security Briefing Report</div>
            <span className="section-badge">{metadata?.generated_at ? new Date(metadata.generated_at).toLocaleDateString() : ''}</span>
          </div>
          <div className="section-body">
            <div className="briefing-content" dangerouslySetInnerHTML={{
              __html: (security_briefing || '')
                .replace(/^# (.+)$/gm, '<h1>$1</h1>')
                .replace(/^## (.+)$/gm, '<h2>$1</h2>')
                .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
                .replace(/\n\|(.+)\|/g, (match) => {
                  const cells = match.trim().split('|').filter(Boolean).map(c => c.trim());
                  if (cells.every(c => c.match(/^-+$/))) return '';
                  return '<tr>' + cells.map(c => `<td>${c}</td>`).join('') + '</tr>';
                })
                .replace(/\n/g, '<br/>')
            }} />
          </div>
        </div>
      )}

      {/* RISK BANNER */}
      <div className={`risk-banner ${risk_posture?.level || 'LOW'}`}>
        <RiskScoreRing score={risk_posture?.score || 0} level={risk_posture?.level || 'LOW'} />
        <div className="risk-info">
          <h2>Overall Risk Level: {risk_posture?.level}</h2>
          <p>{risk_posture?.description}</p>
        </div>
        <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
          <div className="mono text-muted" style={{ fontSize: '0.72rem' }}>Processed in</div>
          <div className="mono" style={{ fontSize: '1.1rem', fontWeight: 700 }}>{metadata?.processing_time_ms}ms</div>
        </div>
      </div>

      {/* STATS GRID */}
      <div className="stats-grid" id="stats-grid">
        <div className="stat-card accent">
          <div className="stat-label">Total Events</div>
          <div className="stat-value">{metadata?.total_events?.toLocaleString()}</div>
          <div className="stat-detail">
            {metadata?.data_sources?.csv_wazuh ? `CSV: ${metadata.data_sources.csv_wazuh}` : `Sim: ${metadata?.data_sources?.simulated}`}
            {metadata?.data_sources?.wazuh_live > 0 ? ` | Live Wazuh: ${metadata.data_sources.wazuh_live}` : ''}
          </div>
        </div>
        <div className="stat-card critical">
          <div className="stat-label">Critical</div>
          <div className="stat-value">{severity_distribution?.CRITICAL || 0}</div>
          <div className="stat-detail">Immediate action required</div>
        </div>
        <div className="stat-card high">
          <div className="stat-label">High</div>
          <div className="stat-value">{severity_distribution?.HIGH || 0}</div>
          <div className="stat-detail">Investigation needed</div>
        </div>
        <div className="stat-card medium">
          <div className="stat-label">Medium</div>
          <div className="stat-value">{severity_distribution?.MEDIUM || 0}</div>
          <div className="stat-detail">Review recommended</div>
        </div>
        <div className="stat-card low">
          <div className="stat-label">Low</div>
          <div className="stat-value">{severity_distribution?.LOW || 0}</div>
          <div className="stat-detail">Informational</div>
        </div>
        <div className="stat-card" style={{}}>
          <div className="stat-label">Compliance</div>
          <div className="stat-value" style={{ color: compliance_summary?.pass_rate >= 50 ? 'var(--low)' : 'var(--critical)' }}>
            {compliance_summary?.pass_rate || 0}%
          </div>
          <div className="stat-detail">SCA pass rate ({compliance_summary?.passed}/{compliance_summary?.total_checks})</div>
        </div>
      </div>

      {/* MAIN GRID - Severity Distribution + Timeline */}
      <div className="dashboard-grid">
        {/* Severity Distribution Chart */}
        <div className="section-card">
          <div className="section-header">
            <div className="section-title">📊 Severity Distribution</div>
            <span className="section-badge">{metadata?.flagged_alerts || 0} flagged</span>
          </div>
          <div className="section-body">
            <DonutChart distribution={severity_distribution || {}} total={metadata?.total_events || 0} />
          </div>
        </div>

        {/* Alert Timeline */}
        <div className="section-card">
          <div className="section-header">
            <div className="section-title">⏱️ Alert Timeline</div>
            <span className="section-badge">Latest first</span>
          </div>
          <div className="section-body" style={{ padding: '8px 12px' }}>
            <div className="timeline">
              {(timeline || []).slice(0, 15).map((item, i) => (
                <div className="timeline-item" key={i} onClick={() => {
                  const alert = (all_alerts || []).find(a => a.event_id === item.event_id);
                  if (alert) setSelectedAlert(alert);
                }}>
                  <div className={`timeline-dot ${item.severity}`} />
                  <div className="timeline-content">
                    <div className="timeline-time">
                      {new Date(item.timestamp).toLocaleTimeString()} — {item.user} — {item.type?.replace(/_/g, ' ')}
                    </div>
                    <div className="timeline-summary" dangerouslySetInnerHTML={{
                      __html: (item.summary || '').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                    }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* TOP ALERTS TABLE */}
      <div className="section-card" style={{ marginBottom: 24 }}>
        <div className="section-header">
          <div className="section-title">🚨 Flagged Alerts — Ranked by Severity</div>
          <span className="section-badge">{filteredAlerts.length} alerts</span>
        </div>
        <div className="filter-bar">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(level => (
            <button
              key={level}
              className={`filter-chip ${severityFilter === level ? 'active' : ''}`}
              onClick={() => setSeverityFilter(level)}
            >
              {level === 'ALL' ? '🔍 All' : `${getSeverityIcon(level)} ${level}`}
            </button>
          ))}
        </div>
        <div className="section-body" style={{ padding: '0 12px 12px', overflowX: 'auto' }}>
          <table className="alerts-table" id="alerts-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Score</th>
                <th>User</th>
                <th>Type</th>
                <th>IP Address</th>
                <th>Location</th>
                <th>Time</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.slice(0, 25).map((alert, i) => (
                <tr key={alert.event_id || i} onClick={() => setSelectedAlert(alert)}>
                  <td>
                    <span className={`severity-badge ${alert.severity?.level}`}>
                      {getSeverityIcon(alert.severity?.level)} {alert.severity?.level}
                    </span>
                  </td>
                  <td>
                    <span className="mono">{((alert.severity?.score || 0) * 100).toFixed(0)}%</span>
                    <div className="score-bar">
                      <div className="score-bar-fill" style={{
                        width: `${(alert.severity?.score || 0) * 100}%`,
                        background: getSeverityColor(alert.severity?.level)
                      }} />
                    </div>
                  </td>
                  <td style={{ fontWeight: 500 }}>{alert.user_id}</td>
                  <td>
                    <span style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                      {(alert.explanation?.threat_type || alert.event_type || '').replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td><span className="mono">{alert.ip_address}</span></td>
                  <td className="text-secondary">{alert.geo_country}</td>
                  <td className="mono text-muted">{new Date(alert.timestamp).toLocaleTimeString()}</td>
                  <td className="text-muted">{alert.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* MITRE + COMPLIANCE GRID */}
      <div className="dashboard-grid">
        {/* MITRE ATT&CK Heatmap */}
        <div className="section-card">
          <div className="section-header">
            <div className="section-title">🗺️ MITRE ATT&CK Coverage</div>
            <span className="section-badge">{mitre_heatmap?.tactics?.length || 0} tactics</span>
          </div>
          <div className="section-body">
            <div style={{ marginBottom: 16 }}>
              <div className="modal-section-title">Tactics</div>
              <div className="mitre-grid">
                {(mitre_heatmap?.tactics || []).map(t => {
                  const maxCount = Math.max(...(mitre_heatmap?.tactics || []).map(x => x.count));
                  return (
                    <div className="mitre-cell" key={t.id}>
                      <div className="mitre-cell-id">{t.id}</div>
                      <div className="mitre-cell-name">{t.name}</div>
                      <div className="mitre-cell-count">{t.count} alert(s)</div>
                      <div className="mitre-cell-bar">
                        <div className="mitre-cell-bar-fill" style={{ width: `${(t.count / maxCount) * 100}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
            <div>
              <div className="modal-section-title">Top Techniques</div>
              <div className="mitre-grid">
                {(mitre_heatmap?.techniques || []).slice(0, 8).map(t => {
                  const maxCount = Math.max(...(mitre_heatmap?.techniques || []).map(x => x.count));
                  return (
                    <div className="mitre-cell" key={t.id}>
                      <div className="mitre-cell-id">{t.id}</div>
                      <div className="mitre-cell-name">{t.name}</div>
                      <div className="mitre-cell-count">{t.count} occurrence(s)</div>
                      <div className="mitre-cell-bar">
                        <div className="mitre-cell-bar-fill" style={{ width: `${(t.count / maxCount) * 100}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Compliance Overview */}
        <div className="section-card">
          <div className="section-header">
            <div className="section-title">✅ Compliance Overview (SCA)</div>
            <span className="section-badge">CIS Benchmark</span>
          </div>
          <div className="section-body">
            <div className="compliance-bar">
              <span className="text-secondary" style={{ fontSize: '0.82rem', whiteSpace: 'nowrap' }}>
                Pass Rate
              </span>
              <div className="compliance-progress">
                <div className="compliance-progress-fill" style={{
                  width: `${compliance_summary?.pass_rate || 0}%`,
                  background: (compliance_summary?.pass_rate || 0) >= 70
                    ? 'linear-gradient(90deg, var(--low), #4ade80)'
                    : (compliance_summary?.pass_rate || 0) >= 40
                      ? 'linear-gradient(90deg, var(--medium), #facc15)'
                      : 'linear-gradient(90deg, var(--critical), #f87171)',
                }} />
              </div>
              <span className="mono" style={{ fontWeight: 700 }}>{compliance_summary?.pass_rate || 0}%</span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginBottom: 16 }}>
              <div className="modal-meta-item">
                <div className="modal-meta-label">Passed</div>
                <div className="modal-meta-value" style={{ color: 'var(--low)' }}>{compliance_summary?.passed || 0}</div>
              </div>
              <div className="modal-meta-item">
                <div className="modal-meta-label">Failed</div>
                <div className="modal-meta-value" style={{ color: 'var(--critical)' }}>{compliance_summary?.failed || 0}</div>
              </div>
              <div className="modal-meta-item">
                <div className="modal-meta-label">N/A</div>
                <div className="modal-meta-value" style={{ color: 'var(--text-muted)' }}>{compliance_summary?.not_applicable || 0}</div>
              </div>
            </div>

            <div className="modal-section-title">Failed Checks</div>
            <div className="compliance-checks">
              {(compliance_summary?.failed_checks || []).map((check, i) => (
                <div className="compliance-check-item" key={i}>
                  <div className="check-title">{check.title}</div>
                  <div className="check-remediation">{check.remediation}</div>
                  {check.compliance?.length > 0 && (
                    <div className="compliance-tags">
                      {check.compliance.map(tag => (
                        <span className="compliance-tag" key={tag}>{tag}</span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* GLOBAL GEO-IP THREAT RADAR */}
      <div className="section-card" style={{ marginBottom: 24, position: 'relative', background: '#070b14', border: '1px solid var(--border-active)', borderRadius: 12, overflow: 'hidden' }}>
        <div className="section-header" style={{ padding: '16px 20px', background: 'rgba(0,0,0,0.6)', borderBottom: '1px solid var(--border-subtle)', position: 'absolute', top: 0, left: 0, right: 0, zIndex: 10 }}>
          <div className="section-title" style={{ color: '#e2e8f0' }}>🌍 Global Threat Radar</div>
          <span className="section-badge" style={{ background: 'var(--critical)', color: '#fff', animation: 'pulse 2s infinite' }}>
            {all_alerts?.filter(a => a.geo_lat && a.geo_lon && a.severity?.level !== 'LOW').length || 0} Active Vectors
          </span>
        </div>
        
        <div style={{ width: '100%', height: '400px', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', marginTop: 40 }}>
          {/* SVG Map Background */}
          <div style={{ width: 800, height: 400, position: 'relative', backgroundImage: 'url("/world-map.svg?v=4")', backgroundSize: '100% 100%', backgroundRepeat: 'no-repeat' }}>
            
            {/* Draw Pulses */}
            {all_alerts?.filter(a => a.geo_lat && a.geo_lon && a.severity?.level !== 'LOW').map((alert, i) => {
              const x = (alert.geo_lon + 180) * (800 / 360);
              const y = (90 - alert.geo_lat) * (400 / 180);
              const isCrit = alert.severity?.level === 'CRITICAL';
              return (
                <div key={i} style={{
                  position: 'absolute',
                  left: `${x}px`,
                  top: `${y}px`,
                  width: 8,
                  height: 8,
                  marginLeft: -4,
                  marginTop: -4,
                  borderRadius: '50%',
                  background: isCrit ? 'var(--critical)' : 'var(--high)',
                  boxShadow: `0 0 10px ${isCrit ? 'var(--critical)' : 'var(--high)'}`,
                  zIndex: 20
                }}>
                  <div style={{
                    position: 'absolute', left: '50%', top: '50%', transform: 'translate(-50%, -50%)',
                    width: 24, height: 24, borderRadius: '50%', border: `1px solid ${isCrit ? 'var(--critical)' : 'var(--high)'}`,
                    animation: 'pulse-ring 2s infinite', opacity: 0.8
                  }} />
                  {/* Tooltip on hover */}
                  <div className="geo-tooltip" style={{
                    position: 'absolute', bottom: '15px', left: '50%', transform: 'translateX(-50%)',
                    background: 'var(--bg-elevated)', border: '1px solid var(--border-active)', padding: '4px 8px',
                    borderRadius: 4, fontSize: '0.65rem', whiteSpace: 'nowrap', opacity: 0, transition: 'opacity 0.2s', pointerEvents: 'none'
                  }}>
                    {alert.ip_address} ({alert.geo_city || alert.geo_country})<br/>
                    {alert.event_type}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Attack Type Summary */}
      <div className="section-card" style={{ marginBottom: 24 }}>
        <div className="section-header">
          <div className="section-title">🎯 Attack Type Summary</div>
          <span className="section-badge">{Object.keys(attack_type_summary || {}).length} types</span>
        </div>
        <div className="section-body">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
            {Object.entries(attack_type_summary || {}).sort((a, b) => b[1].max_severity - a[1].max_severity).map(([type, data]) => (
              <div className="stat-card" key={type} style={{ cursor: 'default' }}>
                <div className="stat-label">{type.replace(/_/g, ' ').toUpperCase()}</div>
                <div className="stat-value" style={{
                  fontSize: '1.5rem',
                  color: data.max_severity >= 0.85 ? 'var(--critical)' :
                    data.max_severity >= 0.6 ? 'var(--high)' :
                      data.max_severity >= 0.3 ? 'var(--medium)' : 'var(--low)'
                }}>
                  {data.count}
                </div>
                <div className="stat-detail">
                  Max severity: {(data.max_severity * 100).toFixed(0)}%
                </div>
                <div className="score-bar" style={{ marginTop: 8 }}>
                  <div className="score-bar-fill" style={{
                    width: `${data.max_severity * 100}%`,
                    background: data.max_severity >= 0.85 ? 'var(--critical)' :
                      data.max_severity >= 0.6 ? 'var(--high)' :
                        data.max_severity >= 0.3 ? 'var(--medium)' : 'var(--low)'
                  }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Processing Info */}
      <div style={{ textAlign: 'center', padding: '20px 0', borderTop: '1px solid var(--border-subtle)' }}>
        <div className="text-muted" style={{ fontSize: '0.75rem' }}>
          Log-Sentinel v{metadata?.pipeline_version} • {metadata?.total_events} events processed •
          Generated {metadata?.generated_at ? new Date(metadata.generated_at).toLocaleString() : ''} •
          Pipeline: {metadata?.processing_time_ms}ms
        </div>
      </div>

      {/* SETTINGS MODAL */}
      {showSettings && (
        <div className="modal-overlay" onClick={() => setShowSettings(false)}>
          <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 500 }}>
            <div className="modal-header">
              <div className="modal-title">⚙️ System Tuner</div>
              <button className="modal-close" onClick={() => setShowSettings(false)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="modal-section-title">ML Isolation Forest Sensitivity</div>
              <p className="text-secondary" style={{ fontSize: '0.85rem', marginBottom: 16 }}>
                Adjust the anomaly detection algorithm threshold. Higher sensitivity flags more events as anomalies.
              </p>
              
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
                <input 
                  type="range" 
                  min="0.01" max="0.99" step="0.01" 
                  value={mlSensitivity} 
                  onChange={(e) => setMlSensitivity(parseFloat(e.target.value))}
                  style={{ flex: 1, accentColor: 'var(--accent-primary)' }}
                />
                <span className="mono" style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--accent-primary)', minWidth: 60 }}>
                  {Math.round(mlSensitivity * 100)}%
                </span>
              </div>

              <button 
                className="btn btn-primary" 
                style={{ width: '100%', padding: '12px' }}
                onClick={() => {
                  setShowSettings(false);
                  fetchReport();
                }}
              >
                Apply & Rerun Pipeline
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ALERT DETAIL MODAL */}
      {selectedAlert && (
        <AlertModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      )}

      {/* SIEM CHAT ASSISTANT */}
      <SIEMChat isOpen={showChat} onClose={() => setShowChat(false)} />

      {/* Chat Toggle FAB */}
      {!showChat && (
        <button
          className="chat-fab"
          onClick={() => setShowChat(true)}
          title="Open SIEM Assistant"
        >
          🤖
        </button>
      )}

      {/* LIVE SOC TICKER */}
      <div className="ticker-wrap">
        <div className="ticker-label">LIVE SOC FEED</div>
        <div className="ticker-viewport">
          <div className="ticker-track">
            {all_alerts?.slice(0, 20).map((alert, i) => (
              <div className="ticker-item" key={i}>
                <span className="ticker-time">
                  [{new Date(alert.timestamp).toLocaleTimeString()}]
                </span>
                <span style={{ 
                    color: alert.severity?.level === 'CRITICAL' ? 'var(--critical)' : 
                           alert.severity?.level === 'HIGH' ? 'var(--high)' : 
                           alert.severity?.level === 'MEDIUM' ? 'var(--medium)' : 'var(--low)',
                    fontWeight: 'bold',
                    marginRight: '6px'
                  }}>
                  {alert.severity?.level || 'INFO'}: 
                </span>
                <span className="ticker-msg">
                  {alert.event_type} on {alert.agent_name} ({alert.ip_address !== 'unknown' ? alert.ip_address : alert.user_id})
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
