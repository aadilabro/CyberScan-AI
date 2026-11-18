import { Activity, ShieldCheck } from 'lucide-react';

export default function Navbar() {
  return (
    <header className="panel flex items-center justify-between px-5 py-4">
      <div className="flex items-center gap-3">
        <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/20">
          <ShieldCheck className="h-6 w-6" />
        </div>

        <div>
          <p className="text-xl font-semibold tracking-tight text-white">ScanShield</p>
          <p className="text-xs text-slate-400">Threat Intelligence & Security Platform</p>
        </div>
      </div>

      <div className="hidden items-center gap-2 rounded-full border border-slate-700 bg-slate-800/80 px-3 py-2 text-sm text-slate-300 sm:flex">
        <Activity className="h-4 w-4 text-emerald-400" />
        Live Detection Feed
      </div>
    </header>
  );
}
