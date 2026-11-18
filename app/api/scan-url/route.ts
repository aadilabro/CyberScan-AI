import { NextRequest, NextResponse } from 'next/server';

const VT_BASE_URL = process.env.VIRUSTOTAL_BASE_URL ?? 'https://www.virustotal.com/api/v3';
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY?.trim();

function buildVirusTotalHeaders(extraHeaders: Record<string, string> = {}) {
  const headers: Record<string, string> = {
    ...extraHeaders,
    'x-apikey': VT_API_KEY ?? '',
  };

  return headers;
}

function getFriendlyVirusTotalError(response: Response) {
  return response.text().then((text) => {
    try {
      const parsed = JSON.parse(text);
      const message =
        parsed?.error?.message ??
        parsed?.message ??
        parsed?.error ??
        'VirusTotal request failed.';

      return typeof message === 'string' ? message : 'VirusTotal request failed.';
    } catch {
      return text || response.statusText || 'VirusTotal request failed.';
    }
  });
}

function hasValidApiKey() {
  return Boolean(
    VT_API_KEY &&
      VT_API_KEY.length > 10 &&
      !VT_API_KEY.toLowerCase().includes('replace_with_') &&
      !VT_API_KEY.toLowerCase().includes('your_virustotal'),
  );
}

function buildMockResult(target: string, type: 'url' | 'domain' = 'url'): ScanResponsePayload {
  const malicious = type === 'url' ? 7 : 5;
  const suspicious = type === 'url' ? 4 : 3;
  const harmless = 11;
  const undetected = 15;

  return {
    target,
    verdict: 'suspicious',
    malicious,
    suspicious,
    harmless,
    undetected,
    totalEngines: malicious + suspicious + harmless + undetected,
    summary: `${target} was analyzed using mock threat intelligence because no active VirusTotal API key is configured.` ,
  };
}

interface VirusTotalStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  timeout?: number;
}

interface ScanResponsePayload {
  target: string;
  verdict: 'malicious' | 'suspicious' | 'safe' | 'undetected';
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  totalEngines: number;
  summary: string;
}

function deriveVerdict(stats: VirusTotalStats): ScanResponsePayload['verdict'] {
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const harmless = stats.harmless ?? 0;
  const undetected = stats.undetected ?? 0;

  if (malicious > 0) return 'malicious';
  if (suspicious > 0) return 'suspicious';
  if (harmless > 0 && undetected === 0) return 'safe';

  return 'undetected';
}

function buildSummary(target: string, verdict: ScanResponsePayload['verdict'], stats: VirusTotalStats): string {
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const harmless = stats.harmless ?? 0;
  const undetected = stats.undetected ?? 0;

  if (verdict === 'malicious') {
    return `${target} triggered ${malicious} malicious detections across the intelligence network.`;
  }

  if (verdict === 'suspicious') {
    return `${target} shows suspicious behavior with ${suspicious} engine hits and ${harmless} clean detections.`;
  }

  if (verdict === 'safe') {
    return `${target} appears safe with ${harmless} clean results and no major detections.`;
  }

  return `${target} remains undetected at this time. ${undetected} engines have not flagged it yet.`;
}

async function fetchAnalysisResult(analysisId: string) {
  const response = await fetch(`${VT_BASE_URL}/analyses/${analysisId}`, {
    method: 'GET',
    headers: buildVirusTotalHeaders({ Accept: 'application/json' }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`VirusTotal analysis request failed: ${errorText || response.statusText}`);
  }

  const data = await response.json();
  return data;
}

export async function POST(request: NextRequest) {
  if (!hasValidApiKey()) {
    const body = await request.json().catch(() => ({ target: '' }));
    const target = typeof body.target === 'string' ? body.target.trim() : 'example.com';
    return NextResponse.json(buildMockResult(target, /^https?:\/\//i.test(target) ? 'url' : 'domain'), { status: 200 });
  }

  try {
    const body = await request.json();
    const rawTarget = typeof body.target === 'string' ? body.target.trim() : '';

    if (!rawTarget) {
      return NextResponse.json({ error: 'A URL or domain is required.' }, { status: 400 });
    }

    const isUrl = /^https?:\/\//i.test(rawTarget);
    const cleanedTarget = isUrl ? rawTarget : rawTarget.replace(/^https?:\/\//i, '');

    let stats: VirusTotalStats = {};

    if (isUrl) {
      const submitResponse = await fetch(`${VT_BASE_URL}/urls`, {
        method: 'POST',
        headers: buildVirusTotalHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }),
        body: new URLSearchParams({ url: rawTarget }).toString(),
      });

      if (!submitResponse.ok) {
        const errorMessage = await getFriendlyVirusTotalError(submitResponse);
        throw new Error(`VirusTotal URL submission failed: ${errorMessage}`);
      }

      const submitData = await submitResponse.json();
      const analysisId = submitData?.data?.id;

      if (!analysisId) {
        throw new Error('No analysis ID was returned for the URL submission.');
      }

      const analysisData = await fetchAnalysisResult(analysisId);
      stats = analysisData?.data?.attributes?.stats ?? {};
    } else {
      const response = await fetch(`${VT_BASE_URL}/domains/${encodeURIComponent(cleanedTarget)}`, {
        method: 'GET',
        headers: buildVirusTotalHeaders({ Accept: 'application/json' }),
      });

      if (!response.ok) {
        const errorMessage = await getFriendlyVirusTotalError(response);
        throw new Error(`VirusTotal domain lookup failed: ${errorMessage}`);
      }

      const data = await response.json();
      stats = data?.data?.attributes?.last_analysis_stats ?? {};
    }

    const verdict = deriveVerdict(stats);
    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const harmless = stats.harmless ?? 0;
    const undetected = stats.undetected ?? 0;
    const totalEngines = malicious + suspicious + harmless + undetected + (stats.timeout ?? 0);

    const payload: ScanResponsePayload = {
      target: rawTarget,
      verdict,
      malicious,
      suspicious,
      harmless,
      undetected,
      totalEngines,
      summary: buildSummary(rawTarget, verdict, stats),
    };

    return NextResponse.json(payload, { status: 200 });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unexpected error while scanning the URL.';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
