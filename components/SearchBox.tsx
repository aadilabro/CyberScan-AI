'use client';

import { ArrowRight, Globe, Loader2, ShieldAlert, UploadCloud } from 'lucide-react';
import { useState } from 'react';
import FileUpload from './FileUpload';
import ResultCard, { ThreatSummary } from './ResultCard';

type ActiveTab = 'url' | 'file';

export default function SearchBox() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('url');
  const [target, setTarget] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ThreatSummary | null>(null);

  const handleScan = async () => {
    if (activeTab === 'url') {
      if (!target.trim()) {
        setError('Please enter a URL or domain to scan.');
        return;
      }
    }

    if (activeTab === 'file' && !selectedFile) {
      setError('Please choose a suspicious file to upload.');
      return;
    }

    setError(null);
    setIsLoading(true);
    setResult(null);

    try {
      let response: Response;

      if (activeTab === 'url') {
        response = await fetch('/api/scan-url', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ target: target.trim() }),
        });
      } else {
        const formData = new FormData();
        formData.append('file', selectedFile as File);

        response = await fetch('/api/scan-file', {
          method: 'POST',
          body: formData,
        });
      }

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data?.error ?? 'The scan request failed. Please try again.');
      }

      setResult(data as ThreatSummary);
    } catch (scanError) {
      const message = scanError instanceof Error ? scanError.message : 'Unexpected scan error.';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="mx-auto max-w-5xl">
      <div className="panel p-4 sm:p-6">
        <div className="flex flex-col gap-4 border-b border-slate-800 pb-5 md:flex-row md:items-center md:justify-between">
          <div className="flex gap-2 rounded-xl border border-slate-800 bg-slate-950/70 p-1">
            <button
              type="button"
              onClick={() => setActiveTab('url')}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition ${
                activeTab === 'url'
                  ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              <Globe className="h-4 w-4" />
              URL / Domain
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('file')}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition ${
                activeTab === 'file'
                  ? 'bg-emerald-500 text-slate-950 shadow-lg shadow-emerald-500/20'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              <UploadCloud className="h-4 w-4" />
              File Scan
            </button>
          </div>

          <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-400">
            <ShieldAlert className="h-4 w-4 text-emerald-400" />
            Secure intelligence checking
          </div>
        </div>

        <div className="mt-5 space-y-4">
          {activeTab === 'url' ? (
            <div className="flex flex-col gap-3 md:flex-row">
              <input
                type="text"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="Enter a URL or domain (e.g. google.com or https://example.com)"
                className="h-14 flex-1 rounded-xl border border-slate-700 bg-slate-950/80 px-4 text-base text-white outline-none transition placeholder:text-slate-500 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20"
              />
              <button
                type="button"
                onClick={handleScan}
                disabled={isLoading}
                className="inline-flex h-14 items-center justify-center gap-2 rounded-xl bg-emerald-500 px-6 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-emerald-900 disabled:text-slate-400"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    Scan Now
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <FileUpload onFileSelected={setSelectedFile} />
              <button
                type="button"
                onClick={handleScan}
                disabled={isLoading || !selectedFile}
                className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-emerald-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-emerald-900 disabled:text-slate-400"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Uploading & Analyzing...
                  </>
                ) : (
                  <>
                    Analyze File
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </button>
            </div>
          )}

          {error ? (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
              {error}
            </div>
          ) : null}
        </div>
      </div>

      <ResultCard result={result} />
    </div>
  );
}
