import { AlertTriangle, CheckCircle2, ShieldAlert, ShieldCheck } from 'lucide-react';

export interface ThreatSummary {
  target: string;
  verdict: 'malicious' | 'suspicious' | 'safe' | 'undetected';
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  totalEngines: number;
  summary: string;
  vendors?: Array<{ name: string; outcome: string }>;
  hashes?: Record<string, string>;
  intelligence?: Record<string, string>;
}

interface ResultCardProps {
  result: ThreatSummary | null;
}

const statusStyles = {
  malicious: {
    label: 'Malicious',
    tone: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
    icon: ShieldAlert,
  },
  suspicious: {
    label: 'Suspicious',
    tone: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
    icon: AlertTriangle,
  },
  safe: {
    label: 'Safe',
    tone: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
    icon: ShieldCheck,
  },
  undetected: {
    label: 'Undetected',
    tone: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
    icon: CheckCircle2,
  },
};

export default function ResultCard({ result }: ResultCardProps) {
  if (!result) {
    return (
      <div className="panel mt-6 p-6 text-slate-300">
        <p className="text-sm text-slate-400">Results will appear here after a scan is completed.</p>
      </div>
    );
  }

  const status = statusStyles[result.verdict];
  const StatusIcon = status.icon;

  return (
    <div className="panel mt-6 overflow-hidden border-slate-800">
      <div className="border-b border-slate-800 bg-slate-900/80 px-5 py-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Threat Analysis</p>
            <h3 className="mt-1 text-xl font-semibold text-white">{result.target}</h3>
          </div>

          <span className={`status-chip ${status.tone}`}>
            <StatusIcon className="h-4 w-4" />
            {status.label}
          </span>
        </div>
      </div>

      <div className="grid gap-4 p-5 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Malicious" value={result.malicious} accent="rose" />
        <MetricCard label="Suspicious" value={result.suspicious} accent="amber" />
        <MetricCard label="Harmless" value={result.harmless} accent="emerald" />
        <MetricCard label="Undetected" value={result.undetected} accent="sky" />
      </div>

      <div className="grid gap-5 border-t border-slate-800 px-5 py-5 lg:grid-cols-[1.2fr_0.8fr]">
        <div>
          <div className="mb-3 flex items-center justify-between">
            <h4 className="text-sm font-semibold uppercase tracking-[0.2em] text-slate-400">Vendor Scan Results</h4>
            <span className="text-xs text-slate-500">{result.totalEngines} engines checked</span>
          </div>

          <div className="space-y-2">
            {(result.vendors ?? []).slice(0, 6).map((vendor) => (
              <div key={vendor.name} className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950/50 px-3 py-2 text-sm text-slate-200">
                <span>{vendor.name}</span>
                <span className={`rounded-full px-2 py-1 text-[10px] font-medium uppercase tracking-[0.16em] ${
                  vendor.outcome === 'malicious'
                    ? 'bg-rose-500/15 text-rose-300'
                    : vendor.outcome === 'suspicious'
                      ? 'bg-amber-500/15 text-amber-300'
                      : vendor.outcome === 'harmless'
                        ? 'bg-emerald-500/15 text-emerald-300'
                        : 'bg-sky-500/15 text-sky-300'
                }`}>
                  {vendor.outcome}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div>
          <h4 className="mb-3 text-sm font-semibold uppercase tracking-[0.2em] text-slate-400">Hash & Intelligence</h4>
          <div className="space-y-3 rounded-2xl border border-slate-800 bg-slate-950/50 p-4 text-sm text-slate-200">
            {(Object.entries(result.hashes ?? {}) || []).map(([name, value]) => (
              <div key={name} className="flex flex-col gap-1">
                <span className="text-[10px] uppercase tracking-[0.2em] text-slate-500">{name}</span>
                <span className="break-all font-mono text-xs text-slate-200">{value}</span>
              </div>
            ))}

            <div className="mt-4 space-y-2 border-t border-slate-800 pt-3 text-xs text-slate-300">
              {Object.entries(result.intelligence ?? {}).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between gap-3">
                  <span className="uppercase tracking-[0.16em] text-slate-500">{key}</span>
                  <span className="text-right text-slate-200">{value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="border-t border-slate-800 px-5 py-4">
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <p className="text-sm text-slate-300">{result.summary}</p>
          <span className="text-xs uppercase tracking-[0.2em] text-slate-400">
            {result.totalEngines} engines checked
          </span>
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent: 'rose' | 'amber' | 'emerald' | 'sky';
}) {
  const accentClasses = {
    rose: 'bg-rose-500/10 text-rose-300 border-rose-500/20',
    amber: 'bg-amber-500/10 text-amber-300 border-amber-500/20',
    emerald: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20',
    sky: 'bg-sky-500/10 text-sky-300 border-sky-500/20',
  };

  return (
    <div className={`rounded-2xl border p-4 ${accentClasses[accent]}`}>
      <p className="text-xs uppercase tracking-[0.18em] text-slate-400">{label}</p>
      <p className="mt-3 text-3xl font-bold">{value}</p>
    </div>
  );
}
