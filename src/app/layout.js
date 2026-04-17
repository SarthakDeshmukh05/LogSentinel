import './globals.css';

export const metadata = {
  title: 'Log-Sentinel | Explainable Security Pipeline',
  description: 'End-to-end explainable cybersecurity pipeline that detects suspicious activities from system logs and explains the reasoning behind each alert in clear human language.',
  keywords: ['cybersecurity', 'log analysis', 'threat detection', 'SIEM', 'explainable AI', 'anomaly detection'],
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="theme-color" content="#060a14" />
        <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>" />
      </head>
      <body>{children}</body>
    </html>
  );
}
