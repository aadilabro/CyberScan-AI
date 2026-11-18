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

function buildMockResult(target: string): ScanResponsePayload {
  return {
    target,
    verdict: 'malicious',
    malicious: 12,
    suspicious: 4,
    harmless: 16,
    undetected: 11,
    totalEngines: 43,
    summary: `${target} was analyzed using mock threat intelligence because no active VirusTotal API key is configured.`,
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
    return `${target} returned ${malicious} malicious engine hits during the file scan.`;
  }

  if (verdict === 'suspicious') {
    return `${target} triggered suspicious flags. ${suspicious} engines marked it as potentially dangerous.`;
  }

  if (verdict === 'safe') {
    return `${target} appears clean, with ${harmless} harmless results and no active detections.`;
  }

  return `${target} is still undetected. ${undetected} engines have not reported a threat yet.`;
}

export async function POST(request: NextRequest) {
  if (!hasValidApiKey()) {
    const formData = await request.formData().catch(() => new FormData());
    const file = formData.get('file');
    const target = file instanceof File ? file.name : 'mocked-threat-sample.bin';
    return NextResponse.json(buildMockResult(target), { status: 200 });
  }

  try {
    const formData = await request.formData();
    const file = formData.get('file');

    if (!(file instanceof File)) {
      return NextResponse.json({ error: 'A valid file upload is required.' }, { status: 400 });
    }

    const uploadForm = new FormData();
    uploadForm.append('file', file, file.name);

    const uploadResponse = await fetch(`${VT_BASE_URL}/files`, {
      method: 'POST',
      headers: buildVirusTotalHeaders(),
      body: uploadForm,
    });

    if (!uploadResponse.ok) {
      const errorMessage = await getFriendlyVirusTotalError(uploadResponse);
      throw new Error(`VirusTotal file upload failed: ${errorMessage}`);
    }

    const uploadData = await uploadResponse.json();
    const analysisId = uploadData?.data?.id;

    if (!analysisId) {
      throw new Error('The file was uploaded but no analysis ID was returned by VirusTotal.');
    }

    const analysisResponse = await fetch(`${VT_BASE_URL}/analyses/${analysisId}`, {
      method: 'GET',
      headers: buildVirusTotalHeaders({ Accept: 'application/json' }),
    });

    if (!analysisResponse.ok) {
      const errorMessage = await getFriendlyVirusTotalError(analysisResponse);
      throw new Error(`VirusTotal analysis failed: ${errorMessage}`);
    }

    const analysisData = await analysisResponse.json();
    const stats: VirusTotalStats = analysisData?.data?.attributes?.stats ?? {};
    const verdict = deriveVerdict(stats);
    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const harmless = stats.harmless ?? 0;
    const undetected = stats.undetected ?? 0;
    const totalEngines = malicious + suspicious + harmless + undetected + (stats.timeout ?? 0);

    const payload: ScanResponsePayload = {
      target: file.name,
      verdict,
      malicious,
      suspicious,
      harmless,
      undetected,
      totalEngines,
      summary: buildSummary(file.name, verdict, stats),
    };

    return NextResponse.json(payload, { status: 200 });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unexpected error while scanning the file.';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
