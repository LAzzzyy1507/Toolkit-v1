import React, { useState, useEffect } from 'react';
import { Newspaper, ExternalLink, ShieldAlert, Clock, AlertTriangle, Loader2, RefreshCw } from 'lucide-react';
import { Explainer } from '../Explainer.tsx';

export const CyberNews: React.FC = () => {
  const [news, setNews] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastFetched, setLastFetched] = useState<string>('');

  const fetchNews = async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch('/api/news');
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'Failed to fetch cybersecurity advisories.');
      }
      setNews(data.news || []);
      setLastFetched(data.lastFetched ? new Date(data.lastFetched).toLocaleTimeString() : 'Recent');
    } catch (err: any) {
      setError(err.message || 'Feed retrieval failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNews();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">Active Cyber Advisories & Threat Feed</h2>
            <Explainer
              term="CISA KEV"
              title="CISA Known Exploited Vulnerabilities (KEV) Catalog"
              summary="The authoritative list of software vulnerabilities with confirmed active exploitation in the wild by threat actors, maintained by the U.S. Cybersecurity and Infrastructure Security Agency."
              whyItMatters="Traditional vulnerability management often struggles with thousands of CVEs. Filtering by CISA KEV allows blue teams to prioritize patching the exact flaws attackers are exploiting right now."
              defenseTip="Establish an automated SLA (e.g. 7 days) to remediate any vulnerability added to the CISA KEV catalog."
              referenceUrl="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time feed of active threat advisories, CISA KEV updates, and critical security disclosures. Cached hourly to minimize upstream latency.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {lastFetched && (
            <span className="text-xs text-slate-400 font-mono">
              Updated: {lastFetched}
            </span>
          )}
          <button
            type="button"
            onClick={fetchNews}
            disabled={loading}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700/80 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh Feed</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-amber-950/40 border border-amber-800/80 rounded-lg flex items-start gap-3 text-amber-200 text-xs">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold block">Feed Notice</span>
            <span>{error}</span>
          </div>
        </div>
      )}

      {loading && news.length === 0 ? (
        <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center gap-3">
          <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
          <span className="text-xs">Aggregating threat advisories and CISA records...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {news.map((item, idx) => (
            <div
              key={item.id || idx}
              className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3 flex flex-col justify-between hover:border-slate-700 transition-colors"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2 text-xs">
                  <span className="font-mono text-cyan-400 font-semibold">{item.source}</span>
                  <span className="font-mono text-slate-400 text-[11px]">{item.published}</span>
                </div>

                <h3 className="text-sm font-bold text-slate-100 leading-snug">{item.title}</h3>

                <p className="text-xs text-slate-300 leading-relaxed">{item.description}</p>

                {item.actionRequired && (
                  <div className="p-2.5 bg-slate-950/70 border border-slate-800 rounded-lg text-xs space-y-1">
                    <span className="text-amber-400 font-semibold block text-[11px]">
                      Required Defensive Action:
                    </span>
                    <span className="text-slate-300 text-[11px] leading-relaxed block">
                      {item.actionRequired}
                    </span>
                  </div>
                )}
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                {item.cveId && item.cveId !== 'N/A' ? (
                  <span className="font-mono text-[11px] text-slate-400">{item.cveId}</span>
                ) : (
                  <span className="text-[11px] text-slate-400">Advisory</span>
                )}

                <a
                  href={item.link}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition-colors font-medium"
                >
                  <span>Official Advisory</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
