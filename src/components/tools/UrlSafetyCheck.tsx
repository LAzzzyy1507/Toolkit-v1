import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Link2, Search, Loader2, CheckCircle2 } from 'lucide-react';
import { Explainer } from '../Explainer.tsx';

export const UrlSafetyCheck: React.FC = () => {
  const [url, setUrl] = useState('https://secure-login.bank-update.xyz/verify-account');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<any>(null);

  const handleCheck = async (testUrl?: string) => {
    const targetUrl = testUrl || url;
    if (!targetUrl.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const resp = await fetch('/api/url-safety', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl.trim() }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'URL safety inspection failed.');
      }
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Inspection failed');
    } finally {
      setLoading(false);
    }
  };

  const sampleUrls = [
    { label: 'Phishing Pattern', url: 'https://secure-login.bank-update.xyz/verify-account' },
    { label: 'Raw IP Host', url: 'http://185.220.101.5:8080/admin/update.exe' },
    { label: 'Legitimate Domain', url: 'https://github.com/torvalds/linux' },
    { label: 'Punycode Homograph', url: 'https://xn--e1afmkfd.xn--p1ai/' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">URL Safety & Threat Inspector</h2>
            <Explainer
              term="URL Reputation"
              title="URL Reputation & Phishing Heuristics"
              summary="Automated analysis of URL lexical composition, domain structure, top-level domain abuse history, and public threat lists (like Google Safe Browsing)."
              whyItMatters="Over 80% of enterprise security breaches initiate via spear-phishing emails containing malicious URLs crafted to harvest credentials or deliver payload droppers."
              defenseTip="Deploy DNS sinkholing (e.g. Quad9 or Cloudflare 1.1.1.2) and email attachment link-rewriting to neutralize deceptive links before users can click them."
            />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Detect deceptive URL structures, homograph attacks, suspicious TLDs, and query Google Safe Browsing reputation feeds.
          </p>
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-slate-400">Samples:</span>
          {sampleUrls.map((s) => (
            <button
              key={s.label}
              type="button"
              onClick={() => {
                setUrl(s.url);
                handleCheck(s.url);
              }}
              className="px-2.5 py-1 text-xs text-slate-300 bg-slate-900 hover:bg-slate-800 hover:text-white border border-slate-700/60 rounded-md transition-colors font-mono cursor-pointer"
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Input */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
            <Link2 className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCheck()}
            placeholder="Paste full URL to inspect (e.g. https://...)..."
            className="w-full pl-9 pr-4 py-2.5 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
        <button
          type="button"
          onClick={() => handleCheck()}
          disabled={loading || !url.trim()}
          className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-400 text-white text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 cursor-pointer shrink-0"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          <span>Inspect URL</span>
        </button>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-lg flex items-start gap-3 text-rose-200 text-xs">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold block">Inspection Error</span>
            <span>{error}</span>
          </div>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          {/* Top Verdict Card */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-5 bg-slate-900/90 border border-slate-800 rounded-xl flex items-center gap-4">
              <div
                className={`w-14 h-14 rounded-xl flex items-center justify-center font-mono font-bold shrink-0 border ${
                  result.verdict === 'SAFE'
                    ? 'bg-emerald-950/80 border-emerald-500 text-emerald-400'
                    : result.verdict === 'SUSPICIOUS'
                    ? 'bg-amber-950/80 border-amber-500 text-amber-400'
                    : 'bg-rose-950/80 border-rose-500 text-rose-400'
                }`}
              >
                {result.verdict === 'SAFE' ? (
                  <CheckCircle2 className="w-7 h-7" />
                ) : result.verdict === 'SUSPICIOUS' ? (
                  <AlertTriangle className="w-7 h-7" />
                ) : (
                  <ShieldAlert className="w-7 h-7" />
                )}
              </div>
              <div>
                <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">
                  Risk Classification
                </div>
                <div
                  className={`text-lg font-extrabold ${
                    result.verdict === 'SAFE'
                      ? 'text-emerald-400'
                      : result.verdict === 'SUSPICIOUS'
                      ? 'text-amber-400'
                      : 'text-rose-400'
                  }`}
                >
                  {result.verdict}
                </div>
                <div className="text-xs text-slate-400 font-mono mt-0.5">
                  Threat Score: {result.riskScore}/100
                </div>
              </div>
            </div>

            <div className="p-5 bg-slate-900/90 border border-slate-800 rounded-xl md:col-span-2 space-y-1.5 text-xs font-mono">
              <div className="flex items-center justify-between text-slate-400 font-sans">
                <span>URL Component Breakdown</span>
                <Explainer
                  term="Deceptive URLs"
                  title="Anatomy of Deceptive URLs"
                  summary="Attackers construct URLs designed to mislead the human eye, placing legitimate brand names in subdomains (e.g. paypal.com.attacker.xyz) or using raw IP addresses."
                  whyItMatters="Mobile browser address bars truncate long URLs, displaying only the first few characters so victims only see 'https://paypal.com...' without realizing the real domain is at the end."
                />
              </div>
              <div className="text-slate-300 truncate">
                <span className="text-slate-400">Host:</span> <span className="text-slate-100">{result.host}</span>
              </div>
              <div className="text-slate-300 truncate">
                <span className="text-slate-400">Path:</span> <span className="text-slate-100">{result.pathname || '/'}</span>
              </div>
              <div className="text-slate-300 truncate">
                <span className="text-slate-400">Protocol:</span> <span className="text-slate-100">{result.protocol}</span>
              </div>
            </div>
          </div>

          {/* Indicators Table */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-5 py-3.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-200">
                Threat Indicators & Heuristic Analysis
              </h3>
              <span className="text-xs text-slate-400">
                {result.indicators?.length || 0} Rule(s) Triggered
              </span>
            </div>

            <div className="divide-y divide-slate-800/70 text-xs">
              {result.indicators && result.indicators.length > 0 ? (
                result.indicators.map((ind: any, i: number) => (
                  <div key={i} className="p-4 flex items-start gap-3">
                    <span
                      className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded border shrink-0 ${
                        ind.risk === 'critical'
                          ? 'bg-rose-950/80 text-rose-300 border-rose-800'
                          : 'bg-amber-950/80 text-amber-300 border-amber-800'
                      }`}
                    >
                      {ind.risk.toUpperCase()}
                    </span>
                    <div className="space-y-0.5">
                      <span className="font-semibold text-slate-100 block">{ind.rule}</span>
                      <p className="text-slate-300 leading-relaxed">{ind.description}</p>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-6 text-center text-slate-400 font-sans">
                  No deceptive heuristics or suspicious keywords detected in the URL structure.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
