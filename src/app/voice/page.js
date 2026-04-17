'use client';
import Script from 'next/script';

export default function VoiceAssistantPage() {
  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#f8fafc',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: "'Inter', sans-serif",
      color: '#0f172a',
      padding: 32,
    }}>
      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: 40 }}>
        <div style={{ fontSize: '3rem', marginBottom: 12 }}>🛡️</div>
        <h1 style={{
          fontSize: '2.25rem',
          fontWeight: 800,
          background: 'linear-gradient(135deg, #4f46e5, #7c3aed)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          color: '#4f46e5', // Fallback
          marginBottom: 8,
          letterSpacing: '-0.025em',
        }}>
          Log-Sentinel Voice Assistant
        </h1>
        <p style={{ color: '#64748b', fontSize: '1.125rem', maxWidth: 500, fontWeight: 500 }}>
          Speak with the AI security analyst. Ask about threats, alerts, 
          compliance, or get a security briefing — all via voice.
        </p>
      </div>

      {/* Voice Widget Container */}
      <div style={{
        background: '#ffffff',
        border: '1px solid #e2e8f0',
        borderRadius: 24,
        padding: 48,
        minWidth: 400,
        minHeight: 320,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.08)',
      }}>
        <elevenlabs-convai agent-id="agent_1501kpd7gt6gfeyr4ft3rdf52z1q"></elevenlabs-convai>
      </div>

      {/* Suggested Prompts */}
      <div style={{ marginTop: 40, textAlign: 'center', maxWidth: 650 }}>
        <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: 16, textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700 }}>
          Try saying
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, justifyContent: 'center' }}>
          {[
            '"What is my current risk level?"',
            '"Summarize today\'s alerts"',
            '"Any brute force attacks?"',
            '"Show compliance status"',
          ].map((prompt, i) => (
            <span key={i} style={{
              background: '#eff6ff',
              border: '1px solid #dbeafe',
              padding: '8px 18px',
              borderRadius: 50,
              fontSize: '0.875rem',
              color: '#2563eb',
              fontWeight: 600,
            }}>
              {prompt}
            </span>
          ))}
        </div>
      </div>

      {/* Back Link */}
      <a
        href="/"
        style={{
          marginTop: 48,
          color: '#94a3b8',
          fontSize: '0.9rem',
          textDecoration: 'none',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          fontWeight: 600,
          transition: 'all 0.2s',
        }}
        onMouseOver={(e) => {
          e.currentTarget.style.color = '#4f46e5';
          e.currentTarget.style.transform = 'translateX(-4px)';
        }}
        onMouseOut={(e) => {
          e.currentTarget.style.color = '#94a3b8';
          e.currentTarget.style.transform = 'translateX(0)';
        }}
      >
        ← Back to Dashboard
      </a>

      {/* ElevenLabs Widget Script */}
      <Script
        src="https://unpkg.com/@elevenlabs/convai-widget-embed"
        strategy="lazyOnload"
      />
    </div>
  );
}
