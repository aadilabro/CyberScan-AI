import Navbar from '@/components/Navbar';
import SearchHub from '@/components/SearchHub';

export default function Home() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-4 pb-16 pt-6 sm:px-6 lg:px-8">
        <Navbar />

        <section className="mt-10">
          <div className="mb-8 text-center">
            <p className="mb-4 inline-flex items-center rounded-full border border-emerald-500/40 bg-emerald-500/10 px-3 py-1 text-[10px] font-medium uppercase tracking-[0.28em] text-emerald-300">
              Threat Intelligence Platform
            </p>
            <h1 className="text-3xl font-bold tracking-tight text-white sm:text-5xl">
              Analyze URLs, domains, and suspicious files with real-time intelligence from the VirusTotal API.
            </h1>
          </div>

          <SearchHub />
        </section>
      </div>
    </main>
  );
}
