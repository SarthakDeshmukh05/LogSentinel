// API Route: /api/analyze — Runs the full Log-Sentinel pipeline
import { runPipeline } from '@/lib/pipeline';

export const dynamic = 'force-dynamic';
export const maxDuration = 30;

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const normalCount = parseInt(searchParams.get('normalCount')) || 250;
    const includeWazuh = searchParams.get('includeWazuh') !== 'false';

    const report = await runPipeline({
      normalCount,
      includeWazuh,
      bruteForceCount: 2,
      impossibleTravelCount: 2,
      offHoursCount: 3,
      privEscCount: 2,
      unknownIPCount: 3,
      eventBurstCount: 1,
      credStuffingCount: 1,
    });

    // Manually stringify to bypass Next.js WASM serializer (avoids usize error)
    const jsonStr = JSON.stringify(report);
    return new Response(jsonStr, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Pipeline error:', error);
    const errJson = JSON.stringify({
      error: 'Pipeline execution failed',
      details: error.message,
    });
    return new Response(errJson, {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

export async function POST(request) {
  try {
    const body = await request.json();
    const report = await runPipeline({
      normalCount: body.normalCount || 250,
      includeWazuh: body.includeWazuh !== false,
      wazuhData: body.wazuhData || null,
      csvData: body.csvEventsClient || null,
      anomalyThreshold: body.anomalyThreshold || 0.08,
      bruteForceCount: body.bruteForceCount || 2,
      impossibleTravelCount: body.impossibleTravelCount || 2,
      offHoursCount: body.offHoursCount || 3,
      privEscCount: body.privEscCount || 2,
      unknownIPCount: body.unknownIPCount || 3,
      eventBurstCount: body.eventBurstCount || 1,
      credStuffingCount: body.credStuffingCount || 1,
      daysBack: body.daysBack || 1,
    });

    const jsonStr = JSON.stringify(report);
    return new Response(jsonStr, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Pipeline error:', error);
    const errJson = JSON.stringify({
      error: 'Pipeline execution failed',
      details: error.message,
    });
    return new Response(errJson, {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}
