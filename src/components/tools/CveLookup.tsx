import React, { useState, useEffect } from 'react';
import { AlertCircle, Search, ShieldAlert, ExternalLink, Filter, Loader2, Info } from 'lucide-react';
import { Explainer } from '../Explainer.tsx';
import { CopyButton } from '../CopyButton.tsx';

export const CveLookup: React.FC = () => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cves, setCves] = useState<any[]>([]);
  const [source, setSource] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  const formatCveBatch = () => {
    if (filteredCves.length === 0) return 'No CVEs found.';
    return [
      `# CVE Search Results (${filteredCves.length} vulnerabilities)`,
      `Query: "${query || 'All Recommended'}" | Filter: ${severityFilter}`,
      '',
      ...filteredCves.map(c => [
        `[${c.cveId}] CVSS: ${c.cvssScore} (${c.severity})`,
        `Title: ${c.title || c.cveId}`,
        `Weakness: ${c.weakness || 'N/A'} | Vector: ${c.vectorString || 'N/A'}`,
        `Summary: ${c.description}`,
        `NVD Link: https://nvd.nist.gov/vuln/detail/${c.cveId}`,
        '--------------------------------------------------',
      ].join('\n'))
    ].join('\n');
  };

  const fetchCves = async (searchQuery = '') => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(`/api/cve?query=${encodeURIComponent(searchQuery)}`);
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'Failed to query CVE catalog');
      }
      setCves(data.results || []);
      setSource(data.source || '');
    } catch (err: any) {
      setError(err.message || 'CVE lookup failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCves('');
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchCves(query);
  };

  const sampleSearches = [
    { label: 'Log4Shell', q: 'CVE-2021-44228' },
    { label: 'XZ Utils Backdoor', q: 'CVE-2024-3094' },
    { label: 'Heartbleed', q: 'CVE-2014-0160' },
    { label: 'EternalBlue', q: 'CVE-2017-0144' },
    { label: 'Spring4Shell', q: 'CVE-2022-22965' },
    { label: 'OpenSSL', q: 'OpenSSL' },
  ];

  const filteredCves = cves.filter((item) => {
    if (severityFilter === 'ALL') return true;
    return item.severity?.toUpperCase() === severityFilter;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">CVE & Vulnerability Explorer</h2>
            <Explainer
              term="CVE & NVD"
              title="Common Vulnerabilities and Exposures (CVE) & NVD"
              summary="CVE is a dictionary of publicly known cybersecurity flaws. The National Vulnerability Database (NVD) analyzes each CVE to assign standardized CVSS severity scores and technical descriptions."
              whyItMatters="Security teams and automated software scanners use CVE IDs to identify which packages in their dependencies have active exploits and require immediate security patches."
              defenseTip="Implement automated Software Bill of Materials (SBOM) and Dependabot/Snyk scanning in CI/CD pipelines to catch vulnerable libraries before deployment."
            />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Search NIST National Vulnerability Database by product, keyword, or CVE identifier. Sorted by CVSS severity.
          </p>
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-slate-400">Milestone CVEs:</span>
          {sampleSearches.map((s) => (
            <button
              key={s.label}
              type="button"
              onClick={() => {
                setQuery(s.q);
                fetchCves(s.q);
              }}
              className="px-2.5 py-1 text-xs text-slate-300 bg-slate-900 hover:bg-slate-800 hover:text-white border border-slate-700/60 rounded-md transition-colors font-mono cursor-pointer"
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Search Bar & Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <form onSubmit={handleSearch} className="flex-1 flex gap-2">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
              <Search className="w-4 h-4" />
            </div>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search keyword (e.g. Apache, OpenSSL) or CVE ID (e.g. CVE-2021-44228)..."
              className="w-full pl-9 pr-4 py-2.5 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-400 text-white text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 cursor-pointer shrink-0"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>Search</span>
          </button>
        </form>

        {/* Severity Filter */}
        <div className="flex items-center gap-1.5 p-1 bg-slate-900 border border-slate-800 rounded-lg shrink-0">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
            <button
              key={sev}
              type="button"
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                severityFilter === sev
                  ? 'bg-slate-800 text-cyan-400 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-lg flex items-start gap-3 text-rose-200 text-xs">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold block">Query Error</span>
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* CVSS Metric Primer Banner */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-200 uppercase tracking-wider font-mono">
              How to Read CVSS v3.1 Scores
            </span>
            <Explainer
              term="CVSS Vectors"
              title="Common Vulnerability Scoring System (CVSS) Vector Metrics"
              summary="CVSS scores range from 0.0 to 10.0: Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0). Vector strings like AV:N/AC:L/PR:N/UI:N describe how the exploit occurs."
              whyItMatters="AV:N means exploitable across the internet. AC:L means low attack complexity. PR:N means no authentication required. UI:N means zero user interaction needed. A score of 10.0 (like Log4Shell) represents maximum danger."
              defenseTip="Prioritize patching vulnerabilities that have both a Critical CVSS score AND appear on CISA's Known Exploited Vulnerabilities catalog."
            />
          </div>
          <p className="text-slate-400 leading-relaxed">
            Vector strings compress attack traits: <code className="text-cyan-300 font-mono">AV:N</code> (Remote Network),{' '}
            <code className="text-cyan-300 font-mono">AC:L</code> (Low Complexity),{' '}
            <code className="text-cyan-300 font-mono">PR:N</code> (No Auth Required),{' '}
            <code className="text-cyan-300 font-mono">UI:N</code> (Zero User Interaction).
          </p>
        </div>
        <div className="shrink-0 flex items-center gap-3">
          <span className="text-slate-400 font-mono text-[11px]">
            Data Source: <span className="text-slate-200">{source || 'NVD & Threat Catalog'}</span>
          </span>
          <CopyButton
            text={formatCveBatch}
            label={`Copy Results (${filteredCves.length})`}
            copiedLabel="Results Copied!"
          />
        </div>
      </div>

      {/* CVE List */}
      <div className="space-y-4">
        {filteredCves.length > 0 ? (
          filteredCves.map((cve) => {
            const score = cve.cvssScore ?? 0;
            const isCritical = score >= 9.0 || cve.severity === 'CRITICAL';
            const isHigh = score >= 7.0 && score < 9.0 || cve.severity === 'HIGH';

            return (
              <div
                key={cve.cveId}
                className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3 hover:border-slate-700/80 transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <span className="font-mono font-bold text-sm text-cyan-400">{cve.cveId}</span>
                    <span
                      className={`text-xs font-mono font-semibold px-2 py-0.5 rounded border ${
                        isCritical
                          ? 'bg-rose-950/80 text-rose-300 border-rose-800/80'
                          : isHigh
                          ? 'bg-amber-950/80 text-amber-300 border-amber-800/80'
                          : 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}
                    >
                      CVSS {score.toFixed(1)} · {cve.severity}
                    </span>
                  </div>

                  <div className="text-xs text-slate-400 font-mono">
                    Published: {cve.publishedDate ? cve.publishedDate.split('T')[0] : 'Historical'}
                  </div>
                </div>

                {cve.title && cve.title !== cve.cveId && (
                  <h3 className="text-sm font-semibold text-slate-100">{cve.title}</h3>
                )}

                <p className="text-xs leading-relaxed text-slate-300">{cve.description}</p>

                <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
                  <div className="flex items-center gap-4 text-slate-400">
                    {cve.weakness && (
                      <span className="font-mono text-[11px] text-slate-400">
                        Weakness: <span className="text-slate-300">{cve.weakness}</span>
                      </span>
                    )}
                    {cve.vectorString && cve.vectorString !== 'N/A' && (
                      <span className="hidden sm:inline font-mono text-[11px] text-cyan-400/90">
                        {cve.vectorString}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <CopyButton
                      text={() => `[${cve.cveId}] CVSS ${cve.cvssScore} (${cve.severity})\nTitle: ${cve.title || cve.cveId}\nWeakness: ${cve.weakness || 'N/A'}\nVector: ${cve.vectorString || 'N/A'}\nSummary: ${cve.description}\nhttps://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                      label="Copy CVE"
                      copiedLabel="Copied!"
                    />
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      <span>NIST Record</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  </div>
                </div>
              </div>
            );
          })
        ) : (
          <div className="p-8 text-center bg-slate-900/40 border border-slate-800 rounded-xl text-slate-400 text-xs">
            No vulnerabilities matched your search term "{query}". Try searching for common terms like "Apache", "SSH", or "OpenSSL".
          </div>
        )}
      </div>
    </div>
  );
};
