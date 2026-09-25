import React, { useState } from 'react';
import { Network, Search, Filter, Shield, AlertCircle, ExternalLink, Loader2 } from 'lucide-react';
import { Explainer } from '../Explainer.tsx';

export const SubdomainFinder: React.FC = () => {
  const [domain, setDomain] = useState('mozilla.org');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<any[]>([]);
  const [filterText, setFilterText] = useState('');
  const [hideWildcards, setHideWildcards] = useState(false);

  const handleSearch = async (targetDomain?: string) => {
    const query = targetDomain || domain;
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(`/api/subdomains?domain=${encodeURIComponent(query.trim())}`);
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'Failed to retrieve subdomains from Certificate Transparency logs.');
      }
      setResults(data.subdomains || []);
    } catch (err: any) {
      setError(err.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const filteredSubdomains = results.filter((item) => {
    if (hideWildcards && item.isWildcard) return false;
    if (!filterText) return true;
    return item.subdomain.toLowerCase().includes(filterText.toLowerCase());
  });

  const sampleTargets = ['mozilla.org', 'nasa.gov', 'stripe.com', 'mit.edu'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">Passive Subdomain Finder</h2>
            <Explainer
              term="Certificate Transparency"
              title="Certificate Transparency (CT) Logs & Attack Surface Discovery"
              summary="An open framework of append-only cryptographically verifiable logs where Certificate Authorities must publicly record every TLS certificate they issue before browsers will trust it."
              whyItMatters="Because CT logs are public, defenders and security analysts can passively discover an organization's subdomains without sending a single network packet to the target's servers, leaving zero log footprint."
              defenseTip="Monitor CT logs via automated webhooks (like crt.sh or Cloudflare CT Alerts) to detect unauthorized certificates issued for your domains within minutes."
              referenceUrl="https://certificate.transparency.dev/"
            />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Query public Certificate Transparency logs (crt.sh) for issued TLS certificates. 100% passive, zero brute-forcing.
          </p>
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-slate-400">Sample targets:</span>
          {sampleTargets.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => {
                setDomain(s);
                handleSearch(s);
              }}
              className="px-2.5 py-1 text-xs text-slate-300 bg-slate-900 hover:bg-slate-800 hover:text-white border border-slate-700/60 rounded-md transition-colors font-mono cursor-pointer"
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Query Bar */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
            <Network className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="Enter root domain (e.g. example.com)..."
            className="w-full pl-9 pr-4 py-2.5 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
        <button
          type="button"
          onClick={() => handleSearch()}
          disabled={loading || !domain.trim()}
          className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-400 text-white text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 cursor-pointer shrink-0"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          <span>Query CT Logs</span>
        </button>
      </div>

      {error && (
        <div className="p-4 bg-amber-950/40 border border-amber-800/80 rounded-lg flex items-start gap-3 text-amber-200 text-xs">
          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold block">Notice</span>
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Results view */}
      {results.length > 0 && (
        <div className="space-y-4">
          {/* Filter & Count toolbar */}
          <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-3">
              <span className="font-mono text-slate-300">
                Found <span className="text-cyan-400 font-semibold">{results.length}</span> unique subdomains in CT records
              </span>
              <Explainer
                term="Shadow IT"
                title="Shadow IT & Attack Surface Mapping"
                summary="Old staging servers, dev portals (e.g. dev-api.company.com), and testing environments frequently persist with outdated software long after a project finishes."
                whyItMatters="Attackers target these forgotten subdomains because they typically lack Web Application Firewall (WAF) coverage and up-to-date patch management."
                defenseTip="Regularly review CT logs to decommission orphaned DNS records and decommission unmanaged test endpoints."
              />
            </div>

            <div className="flex items-center gap-3">
              <input
                type="text"
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                placeholder="Filter subdomains..."
                className="px-2.5 py-1 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono w-40"
              />

              <label className="flex items-center gap-1.5 text-slate-400 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={hideWildcards}
                  onChange={(e) => setHideWildcards(e.target.checked)}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0"
                />
                <span>Hide Wildcards</span>
              </label>
            </div>
          </div>

          {/* Table */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
            <div className="max-h-96 overflow-y-auto divide-y divide-slate-800/70 text-xs font-mono">
              {filteredSubdomains.length > 0 ? (
                filteredSubdomains.map((item, index) => (
                  <div
                    key={index}
                    className="p-3.5 flex items-center justify-between hover:bg-slate-800/40 transition-colors"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-slate-400 text-[11px] w-8 shrink-0">{index + 1}.</span>
                      <span
                        className={`truncate font-medium ${
                          item.isWildcard ? 'text-amber-300' : 'text-slate-100'
                        }`}
                      >
                        {item.subdomain}
                      </span>
                    </div>

                    <div className="flex items-center gap-4 text-slate-400 text-[11px] shrink-0 font-sans">
                      <span className="hidden md:inline truncate max-w-xs">{item.issuer}</span>
                      <span className="text-slate-400 font-mono">{item.loggedAt?.split('T')[0]}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-8 text-center text-slate-400 font-sans">
                  No subdomains match your current filter query.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
