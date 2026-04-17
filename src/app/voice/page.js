'use client';
import Script from 'next/script';

export default function VoiceAssistantPage() {
  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: "'Inter', sans-serif",
      color: '#e2e8f0',
      padding: 32,
    }}>
      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: 40 }}>
        <div style={{ fontSize: '3rem', marginBottom: 12 }}>🛡️</div>
        <h1 style={{
          fontSize: '2rem',
          fontWeight: 800,
          background: 'linear-gradient(135deg, #6366f1, #8b5cf6, #a78bfa)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          marginBottom: 8,
        }}>
          Log-Sentinel Voice Assistant
        </h1>
        <p style={{ color: '#94a3b8', fontSize: '1rem', maxWidth: 500 }}>
          Speak with the AI security analyst. Ask about threats, alerts, compliance status, 
          or get an executive briefing — all through voice.
        </p>
      </div>

      {/* Voice Widget Container */}
      <div style={{
        background: 'rgba(255,255,255,0.05)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: 20,
        padding: 40,
        minWidth: 360,
        minHeight: 300,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backdropFilter: 'blur(12px)',
        boxShadow: '0 20px 60px rgba(0,0,0,0.4)',
      }}>
        <elevenlabs-convai agent-id="agent_1501kpd7gt6gfeyr4ft3rdf52z1q"></elevenlabs-convai>
      </div>

      {/* Suggested Prompts */}
      <div style={{ marginTop: 32, textAlign: 'center', maxWidth: 600 }}>
        <div style={{ fontSize: '0.8rem', color: '#64748b', marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>
          Try saying
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center' }}>
          {[
            '"What is my current risk level?"',
            '"Summarize today\'s alerts"',
            '"Any brute force attacks?"',
            '"Show compliance status"',
          ].map((prompt, i) => (
            <span key={i} style={{
              background: 'rgba(99,102,241,0.15)',
              border: '1px solid rgba(99,102,241,0.3)',
              padding: '6px 14px',
              borderRadius: 20,
              fontSize: '0.82rem',
              color: '#a5b4fc',
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
          marginTop: 40,
          color: '#64748b',
          fontSize: '0.85rem',
          textDecoration: 'none',
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          transition: 'color 0.2s',
        }}
        onMouseOver={(e) => e.target.style.color = '#a5b4fc'}
        onMouseOut={(e) => e.target.style.color = '#64748b'}
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
