'use client';

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';

export default function IncidentReportPage() {
  const searchParams = useSearchParams();
  const [reportData, setReportData] = useState(null);

  useEffect(() => {
    // If the user navigated here with a specific event ID, we try to load it from localStorage
    const eventId = searchParams.get('event_id');
    try {
      if (eventId) {
        const storedReports = JSON.parse(localStorage.getItem('logsentinel_reports') || '{}');
        if (storedReports[eventId]) {
          setReportData(storedReports[eventId]);
          return;
        }
      }
    } catch (e) {
      console.error('Failed to load report data', e);
    }

    // Default Fallback Template (The exact ISRO Reference Data from User Screenshots)
    setReportData({
      detection_date: '2024-01-15',
      detection_time: '14:32:45 IST',
      occurrence_date: '2024-01-14',
      occurrence_time: '23:15:20 IST',
      source_ip: '185.220.101.47',
      source_location: 'Unknown / Eastern Europe (Suspected VPN/Proxy)',
      source_port: '443',
      dest_ip: '192.168.45.128',
      dest_system_id: 'ISRO-SRV-DB-01',
      dest_port: '3306',
      summary: [
        'On January 14, 2024 at 23:15:20 IST, our Security Information and Event Management (SIEM) system detected anomalous database query patterns originating from an external IP address (185.220.101.47). The attack exploited a SQL injection vulnerability in the mission planning web application interface, allowing the attacker to gain unauthorized access to the MySQL database server (ISRO-SRV-DB-01).',
        'The attacker successfully executed malicious SQL queries that bypassed authentication mechanisms and escalated privileges to database administrator level. Initial analysis indicates the attacker accessed several database tables containing operational scheduling data, though no sensitive mission-critical information appears to have been exfiltrated. The incident was automatically detected by our SIEM system on January 15, 2024 at 14:32:45 IST through pattern recognition of unusual query structures and privilege escalation attempts.',
        'Immediate containment measures were implemented, including network isolation of the affected database server and termination of all active database connections. The attack vector was successfully blocked, and the system was restored to normal operations after security patches were applied.'
      ],
      systems_affected: 'ISRO-SRV-DB-01 (Primary Database Server), ISRO-WEB-APP-03 (Mission Planning Web Application), ISRO-NET-FW-02 (Network Firewall - Configuration Modified)',
      data_risk: 'Medium - Potential exposure of non-sensitive operational data including mission scheduling information, satellite tracking coordinates, and ground station communication logs. No classified or mission-critical payload data was accessed. Risk of data integrity compromise is low as no write operations were confirmed.',
      downtime: '2 hours 15 minutes (14:32:45 IST to 16:47:30 IST on January 15, 2024)'
    });
  }, [searchParams]);

  if (!reportData) return <div style={{ padding: 40, color: '#333' }}>Loading report...</div>;

  return (
    <div className="ir-report-body">
      {/* Utility Header - Hidden during print */}
      <div className="no-print" style={{ maxWidth: 900, margin: '0 auto 20px', display: 'flex', justifyContent: 'flex-end' }}>
        <button 
          onClick={() => window.print()}
          style={{
            background: '#f26522', color: 'white', border: 'none', padding: '8px 16px', 
            borderRadius: 4, fontWeight: 600, cursor: 'pointer', display: 'flex', gap: 8, alignItems: 'center'
          }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
          Export to PDF
        </button>
      </div>

      <div className="ir-report-page">
        {/* SECTION 1: INCIDENT DETECTION DETAILS */}
        <div className="ir-section">
          <div className="ir-section-title">Incident Detection Details</div>
          
          <div className="ir-field-group">
            <span className="ir-label">Date Incident Detected:</span>
            <div className="ir-value">{reportData.detection_date}</div>
          </div>
          
          <div className="ir-field-group">
            <span className="ir-label">Time Incident Detected:</span>
            <div className="ir-value">{reportData.detection_time}</div>
          </div>
          
          <div className="ir-field-group">
            <span className="ir-label">Date Incident Occurred:</span>
            <div className="ir-value">{reportData.occurrence_date}</div>
          </div>
          
          <div className="ir-field-group">
            <span className="ir-label">Time Incident Occurred:</span>
            <div className="ir-value">{reportData.occurrence_time}</div>
          </div>
        </div>

        {/* SECTION 2: NETWORK ENDPOINT DETAILS */}
        <div className="ir-section">
          <div className="ir-section-title">Network Endpoint Details</div>
          
          <div className="ir-nested-box">
            <div className="ir-section-subtitle">Source Information</div>
            <div className="ir-field-group">
              <span className="ir-label">Source IP Address:</span>
              <div className="ir-value">{reportData.source_ip}</div>
            </div>
            <div className="ir-field-group">
              <span className="ir-label">Source Address / Location:</span>
              <div className="ir-value">{reportData.source_location}</div>
            </div>
            <div className="ir-field-group">
              <span className="ir-label">Source Port (if applicable):</span>
              <div className="ir-value">{reportData.source_port}</div>
            </div>
          </div>

          <div className="ir-nested-box">
            <div className="ir-section-subtitle">Destination Information</div>
            <div className="ir-field-group">
              <span className="ir-label">Destination IP Address:</span>
              <div className="ir-value">{reportData.dest_ip}</div>
            </div>
            <div className="ir-field-group">
              <span className="ir-label">Destination System ID / Name:</span>
              <div className="ir-value">{reportData.dest_system_id}</div>
            </div>
            <div className="ir-field-group">
              <span className="ir-label">Destination Port (if applicable):</span>
              <div className="ir-value">{reportData.dest_port}</div>
            </div>
          </div>
        </div>

        {/* SECTION 3: INCIDENT SUMMARY */}
        <div className="ir-section">
          <div className="ir-section-title">Incident Summary</div>
          <div className="ir-field-group">
            <span className="ir-label">Summary:</span>
            <div className="ir-textarea">
              {Array.isArray(reportData.summary) 
                ? reportData.summary.map((paragraph, i) => <p key={i}>{paragraph}</p>)
                : <p>{reportData.summary}</p>
              }
            </div>
          </div>
        </div>

        {/* SECTION 4: IMPACT ASSESSMENT */}
        <div className="ir-section">
          <div className="ir-section-title">Impact Assessment</div>
          <div className="ir-field-group">
            <span className="ir-label">Systems Affected:</span>
            <div className="ir-value">{reportData.systems_affected}</div>
          </div>
          <div className="ir-field-group">
            <span className="ir-label">Data Risk Assessment:</span>
            <div className="ir-textarea">{reportData.data_risk}</div>
          </div>
          <div className="ir-field-group">
            <span className="ir-label">Downtime:</span>
            <div className="ir-value">{reportData.downtime}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
