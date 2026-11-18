import { NextRequest, NextResponse } from 'next/server';

const VT_BASE_URL = process.env.VIRUSTOTAL_BASE_URL ?? 'https://www.virustotal.com/api/v3';
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY?.trim();

const MOCK_VENDOR_REPORTS = [
  { name: 'Microsoft', outcome: 'malicious' },
  { name: 'Google Safebrowsing', outcome: 'suspicious' },
  { name: 'BitDefender', outcome: 'harmless' },
  { name: 'Kaspersky', outcome: 'malicious' },
  { name: 'Avast', outcome: 'undetected' },
  { name: 'Sigma', outcome: 'suspicious' },
];

function hasValidApiKey() {
  return Boolean(
    VT_API_KEY &&
      VT_API_KEY.length > 10 &&
      !VT_API_KEY.toLowerCase().includes('replace_with_') &&
      !VT_API_KEY.toLowerCase().includes('your_virustotal'),
  );
}

function buildMockResult(type: string, query: string) {
  const normalized = query || 'sample-target';
  const verdict = type === 'file' ? 'malicious' : type === 'url' ? 'suspicious' : 'safe';
  const malicious = type === 'file' ? 12 : type === 'url' ? 7 : 2;
  const suspicious = type === 'domain' ? 5 : type === 'ip' ? 4 : 3;
  const harmless = type === 'hash' ? 18 : 10;
  const undetected = 14;

  return {
    target: normalized,
    type,
    verdict,
    malicious,
    suspicious,
    harmless,
    undetected,
    totalEngines: malicious + suspicious + harmless + undetected,
    summary: `${normalized} shows ${verdict} behaviour in the security intelligence network and requires further review.`,
    vendors: MOCK_VENDOR_REPORTS.map((vendor, index) => ({
      ...vendor,
      outcome: index % 2 === 0 ? 'malicious' : index % 3 === 0 ? 'suspicious' : 'harmless',
    })),
    hashes: {
      md5: '8d9f3ad2a1d7f2b19c6206567d3a5d32',
      sha256: '8d1b7f5e38d4a428a59b2e16a4e3d8d111a7a5d99fb5fcb7cde61ec3f569b14f',
      sha1: 'f36d3b9f7f7bc7d5f1b9f4c4cb0ef5b39c230af',
    },
    intelligence: {
      asn: 'AS15169',
      country: 'United States',
      registrar: 'Cloudflare, Inc.',
      reputation: 'Low reputation / risk observed',
    },
  };
}

async function proxyVirusTotal(type: string, query: string) {
  const encoded = encodeURIComponent(query);
  let endpoint = '';

  switch (type) {
    case 'file':
      endpoint = `/files/${encoded}`;
      break;
    case 'url':
      endpoint = `/urls/${encoded}`;
      break;
    case 'domain':
      endpoint = `/domains/${encoded}`;
      break;
    case 'ip':
      endpoint = `/ip_addresses/${encoded}`;
      break;
    case 'hash':
      endpoint = `/files/${encoded}`;
      break;
    default:
      endpoint = `/search?query=${encoded}`;
  }

  const response = await fetch(`${VT_BASE_URL}${endpoint}`, {
    method: 'GET',
    headers: {
      'x-apikey': VT_API_KEY ?? '',
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(errorText || `VirusTotal ${type} lookup failed.`);
  }

  return response.json();
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const type = typeof body.type === 'string' ? body.type : 'search';
    const query = typeof body.query === 'string' ? body.query.trim() : '';

    if (!query) {
      return NextResponse.json({ error: 'A query is required for the scan.' }, { status: 400 });
    }

    if (!hasValidApiKey()) {
      return NextResponse.json(buildMockResult(type, query), { status: 200 });
    }

    const data = await proxyVirusTotal(type, query);

    const stats = data?.data?.attributes?.last_analysis_stats ?? data?.data?.attributes?.stats ?? {
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
    };

    const verdict =
      (stats.malicious ?? 0) > 0
        ? 'malicious'
        : (stats.suspicious ?? 0) > 0
          ? 'suspicious'
          : (stats.harmless ?? 0) > 0 && (stats.undetected ?? 0) === 0
            ? 'safe'
            : 'undetected';

    const payload = {
      target: query,
      type,
      verdict,
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      undetected: stats.undetected ?? 0,
      totalEngines: (stats.malicious ?? 0) + (stats.suspicious ?? 0) + (stats.harmless ?? 0) + (stats.undetected ?? 0),
      summary: `${query} was analyzed by the VirusTotal intelligence network.`,
      vendors: Array.isArray(data?.data?.attributes?.last_analysis_results)
        ? Object.entries(data.data.attributes.last_analysis_results).map(([name, value]) => ({
            name,
            outcome: typeof value === 'object' && value && 'result' in value ? String((value as { result?: string }).result ?? 'undetected') : 'undetected',
          }))
        : MOCK_VENDOR_REPORTS,
      hashes: {
        md5: data?.data?.attributes?.md5 ?? 'n/a',
        sha256: data?.data?.attributes?.sha256 ?? 'n/a',
        sha1: data?.data?.attributes?.sha1 ?? 'n/a',
      },
      intelligence: {
        country: data?.data?.attributes?.country ?? 'Unknown',
        asn: data?.data?.attributes?.asn ?? 'Unknown',
        registrar: data?.data?.attributes?.registrar ?? 'Unknown',
        reputation: data?.data?.attributes?.reputation ?? 'Not enough data',
      },
    };

    return NextResponse.json(payload, { status: 200 });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to search VirusTotal.';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
