import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, Lock, AlertTriangle, CheckCircle2, XCircle, Search, Loader2 } from 'lucide-react';
import { Explainer } from '../Explainer.tsx';

export const CertHeaderInspector: React.FC = () => {
  const [target, setTarget] = useState('github.com');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<any>(null);

  const handleInspect = async (inspectTarget?: string) => {
    const host = inspectTarget || target;
    if (!host.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(`/api/cert-headers?target=${encodeURIComponent(host.trim())}`);
      const json = await resp.json();
      if (!resp.ok) {
        throw new Error(json.error || 'Inspection failed');
      }
      setData(json);
    } catch (err: any) {
      setError(err.message || 'Inspection failed');
    } finally {
      setLoading(false);
    }
  };

  const sampleTargets = ['github.com', 'google.com', 'wikipedia.org', 'cloudflare.com'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">
              Certificate & Security Header Inspector
            </h2>
            <Explainer
              term="TLS & Headers"
              title="Transport Layer Security (TLS) & HTTP Defense Headers"
              summary="Security headers instruct web browsers how to handle sensitive resources, restrict framing, enforce encryption, and prevent Cross-Site Scripting (XSS)."
              whyItMatters="Without security headers like HSTS and CSP, modern browsers default to permissive behaviors that leave users susceptible to Man-in-the-Middle (MITM) downgrade attacks, Clickjacking, and malicious script execution."
              defenseTip="Aim for Grade A/A+ by implementing Content-Security-Policy with strict nonces or hashes, HSTS with preload, and nosniff."
            />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Audit TLS certificate validity, cipher suites, and evaluate HTTP security posture with actionable defense grades.
          </p>
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-slate-400">Try host:</span>
          {sampleTargets.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => {
                setTarget(s);
                handleInspect(s);
              }}
              className="px-2.5 py-1 text-xs text-slate-300 bg-slate-900 hover:bg-slate-800 hover:text-white border border-slate-700/60 rounded-md transition-colors font-mono cursor-pointer"
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Input */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
            <Lock className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleInspect()}
            placeholder="Enter hostname (e.g. example.com)..."
            className="w-full pl-9 pr-4 py-2.5 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
        <button
          type="button"
          onClick={() => handleInspect()}
          disabled={loading || !target.trim()}
          className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-400 text-white text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 cursor-pointer shrink-0"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          <span>Audit Host</span>
        </button>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-lg flex items-start gap-3 text-rose-200 text-xs">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold block">Audit Interrupted</span>
            <span>{error}</span>
          </div>
        </div>
      )}

      {data && (
        <div className="space-y-6">
          {/* Top Grade & Overview Card */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Grade Card */}
            <div className="p-5 bg-slate-900/90 border border-slate-800 rounded-xl flex items-center gap-4">
              <div
                className={`w-16 h-16 rounded-xl flex items-center justify-center font-mono text-3xl font-extrabold shrink-0 border ${
                  data.securityHeaders?.grade?.startsWith('A')
                    ? 'bg-emerald-950/80 border-emerald-500 text-emerald-400'
                    : data.securityHeaders?.grade === 'B'
                    ? 'bg-cyan-950/80 border-cyan-500 text-cyan-400'
                    : data.securityHeaders?.grade === 'C'
                    ? 'bg-amber-950/80 border-amber-500 text-amber-400'
                    : 'bg-rose-950/80 border-rose-500 text-rose-400'
                }`}
              >
                {data.securityHeaders?.grade || 'N/A'}
              </div>
              <div>
                <div className="flex items-center gap-1">
                  <span className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Security Grade</span>
                  <Explainer
                    term="Header Score"
                    title="Security Header Grading System"
                    summary="Calculated by assessing critical browser defenses against XSS, clickjacking, MIME-sniffing, and SSL stripping."
                    whyItMatters="High grades indicate a defense-in-depth web architecture where user browser sessions are actively safeguarded against client-side exploitation."
                  />
                </div>
                <div className="text-base font-bold text-slate-100 mt-0.5">
                  Score: {data.securityHeaders?.score ?? 0}/100
                </div>
                <div className="text-xs text-slate-400 mt-0.5">
                  HTTP Status: {data.securityHeaders?.statusCode || '200 OK'}
                </div>
              </div>
            </div>

            {/* Certificate Status */}
            <div className="p-5 bg-slate-900/90 border border-slate-800 rounded-xl md:col-span-3">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span className="uppercase tracking-wider font-semibold text-slate-200">
                    SSL / TLS Certificate Health
                  </span>
                </div>
                <Explainer
                  term="X.509 Certificate"
                  title="X.509 Public Key Certificate & Expiry"
                  summary="Cryptographic identity document issued by a trusted Certificate Authority (CA) binding a public key to domain names."
                  whyItMatters="Expired or revoked certificates trigger full browser warning interstitials ('Your connection is not private'), causing complete service outage and user distrust."
                  defenseTip="Automate certificate renewal using ACME / Let's Encrypt at 30 days prior to expiry."
                />
              </div>

              {data.certificate?.error ? (
                <div className="text-xs text-amber-400 font-mono">{data.certificate.error}</div>
              ) : (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  <div>
                    <span className="text-slate-400 block text-[11px]">Issuer CA:</span>
                    <span className="text-slate-200 font-semibold truncate block">
                      {data.certificate?.issuer?.O || data.certificate?.issuer?.CN || 'Standard CA'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Validity Remaining:</span>
                    <span
                      className={`font-semibold ${
                        (data.certificate?.daysRemaining || 0) < 15 ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {data.certificate?.daysRemaining ?? 'N/A'} Days
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Protocol:</span>
                    <span className="text-slate-200">{data.certificate?.protocol || 'TLSv1.3'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Cipher Suite:</span>
                    <span className="text-slate-200 truncate block">{data.certificate?.cipherName || 'AES-GCM'}</span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Key Security Headers Inspection Table */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-5 py-3.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-200">
                HTTP Security Headers Audit
              </h3>
              <span className="text-xs text-slate-400">OWASP Secure Headers Checklist</span>
            </div>

            <div className="divide-y divide-slate-800/70 text-xs">
              {/* CSP */}
              <div className="p-4 flex flex-col sm:flex-row sm:items-start gap-4">
                <div className="w-48 shrink-0">
                  <div className="flex items-center gap-1.5 font-mono font-semibold text-slate-100">
                    {data.securityHeaders?.headers?.csp ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                    )}
                    <span>Content-Security-Policy</span>
                    <Explainer
                      term="CSP"
                      title="Content-Security-Policy (CSP)"
                      summary="HTTP response header that restricts which domain origins can load scripts, stylesheets, images, and iframes into the page."
                      whyItMatters="CSP is the primary browser defense against Cross-Site Scripting (XSS). Even if an attacker injects a `<script>` tag, the browser blocks execution unless allowed by CSP."
                      defenseTip="Use nonces or hashes instead of 'unsafe-inline' to achieve robust XSS protection."
                    />
                  </div>
                </div>
                <div className="flex-1 font-mono break-all text-slate-300">
                  {data.securityHeaders?.headers?.csp ? (
                    <div className="p-2 bg-slate-950/70 rounded border border-slate-800 text-[11px] text-emerald-300/90">
                      {data.securityHeaders.headers.csp}
                    </div>
                  ) : (
                    <span className="text-rose-400 font-sans">
                      Missing. Leaves client vulnerable to Cross-Site Scripting (XSS) and data exfiltration.
                    </span>
                  )}
                </div>
              </div>

              {/* HSTS */}
              <div className="p-4 flex flex-col sm:flex-row sm:items-start gap-4">
                <div className="w-48 shrink-0">
                  <div className="flex items-center gap-1.5 font-mono font-semibold text-slate-100">
                    {data.securityHeaders?.headers?.hsts ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                    )}
                    <span>Strict-Transport-Security</span>
                    <Explainer
                      term="HSTS"
                      title="Strict-Transport-Security (HSTS)"
                      summary="Forces browsers to communicate exclusively over HTTPS, automatically upgrading any insecure HTTP URLs."
                      whyItMatters="Protects against SSL Stripping and cookie interception on public Wi-Fi networks before the initial TLS handshake occurs."
                      defenseTip="Configure: max-age=31536000; includeSubDomains; preload."
                    />
                  </div>
                </div>
                <div className="flex-1 font-mono break-all text-slate-300">
                  {data.securityHeaders?.headers?.hsts ? (
                    <div className="p-2 bg-slate-950/70 rounded border border-slate-800 text-[11px] text-emerald-300/90">
                      {data.securityHeaders.headers.hsts}
                    </div>
                  ) : (
                    <span className="text-rose-400 font-sans">
                      Missing. Users can be subjected to SSL stripping attacks on unencrypted Wi-Fi networks.
                    </span>
                  )}
                </div>
              </div>

              {/* X-Frame-Options */}
              <div className="p-4 flex flex-col sm:flex-row sm:items-start gap-4">
                <div className="w-48 shrink-0">
                  <div className="flex items-center gap-1.5 font-mono font-semibold text-slate-100">
                    {data.securityHeaders?.headers?.xfo ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-amber-400 shrink-0" />
                    )}
                    <span>X-Frame-Options</span>
                    <Explainer
                      term="X-Frame-Options"
                      title="X-Frame-Options (Clickjacking Defense)"
                      summary="Specifies whether a page can be embedded inside `<frame>`, `<iframe>`, `<embed>`, or `<object>` elements."
                      whyItMatters="Prevents Clickjacking attacks where an attacker overlays an invisible iframe of your site over a tempting button, tricking users into clicking unauthorized actions."
                      defenseTip="Set to DENY or SAMEORIGIN (or use CSP frame-ancestors 'self')."
                    />
                  </div>
                </div>
                <div className="flex-1 font-mono break-all text-slate-300">
                  {data.securityHeaders?.headers?.xfo ? (
                    <div className="p-2 bg-slate-950/70 rounded border border-slate-800 text-[11px] text-emerald-300/90">
                      {data.securityHeaders.headers.xfo}
                    </div>
                  ) : (
                    <span className="text-amber-400 font-sans">
                      Not explicitly set (verify if covered by CSP frame-ancestors).
                    </span>
                  )}
                </div>
              </div>

              {/* X-Content-Type-Options */}
              <div className="p-4 flex flex-col sm:flex-row sm:items-start gap-4">
                <div className="w-48 shrink-0">
                  <div className="flex items-center gap-1.5 font-mono font-semibold text-slate-100">
                    {data.securityHeaders?.headers?.xcto ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                    )}
                    <span>X-Content-Type-Options</span>
                    <Explainer
                      term="XCTO"
                      title="X-Content-Type-Options: nosniff"
                      summary="Prevents the browser from MIME-sniffing a response away from the declared content-type."
                      whyItMatters="Without this, an attacker could upload an image containing JavaScript. If the browser sniffs it as text/html, it executes malicious script in the victim's origin context."
                      defenseTip="Always set: X-Content-Type-Options: nosniff."
                    />
                  </div>
                </div>
                <div className="flex-1 font-mono break-all text-slate-300">
                  {data.securityHeaders?.headers?.xcto ? (
                    <div className="p-2 bg-slate-950/70 rounded border border-slate-800 text-[11px] text-emerald-300/90">
                      {data.securityHeaders.headers.xcto}
                    </div>
                  ) : (
                    <span className="text-rose-400 font-sans">
                      Missing. Browser may execute scripts masquerading as innocent media files.
                    </span>
                  )}
                </div>
              </div>

              {/* Referrer-Policy */}
              <div className="p-4 flex flex-col sm:flex-row sm:items-start gap-4">
                <div className="w-48 shrink-0">
                  <div className="flex items-center gap-1.5 font-mono font-semibold text-slate-100">
                    {data.securityHeaders?.headers?.rp ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-amber-400 shrink-0" />
                    )}
                    <span>Referrer-Policy</span>
                    <Explainer
                      term="Referrer-Policy"
                      title="Referrer-Policy & Privacy Leaks"
                      summary="Controls how much referrer information (the URL the user was previously on) is sent along with requests."
                      whyItMatters="Prevents leaking sensitive query parameters (e.g. `?token=xyz` or user email addresses) to external third-party servers or CDNs."
                      defenseTip="Use: strict-origin-when-cross-origin or no-referrer."
                    />
                  </div>
                </div>
                <div className="flex-1 font-mono break-all text-slate-300">
                  {data.securityHeaders?.headers?.rp ? (
                    <div className="p-2 bg-slate-950/70 rounded border border-slate-800 text-[11px] text-emerald-300/90">
                      {data.securityHeaders.headers.rp}
                    </div>
                  ) : (
                    <span className="text-amber-400 font-sans">
                      Missing. May leak URL path and session parameters across cross-origin requests.
                    </span>
                  )}
                </div>
              </div>

              {/* Server / Info Leak */}
              <div className="p-4 flex flex-col sm:flex-row sm:items-start gap-4">
                <div className="w-48 shrink-0">
                  <div className="flex items-center gap-1.5 font-mono font-semibold text-slate-100">
                    {!data.securityHeaders?.headers?.serverHeader && !data.securityHeaders?.headers?.poweredBy ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                    )}
                    <span>Server Disclosure</span>
                    <Explainer
                      term="Info Leak"
                      title="Server Banner & Information Disclosure"
                      summary="Headers like 'Server' and 'X-Powered-By' announce the exact web server (e.g. Apache/2.4.49, Express) and operating system version."
                      whyItMatters="Gives automated exploit scanners the exact software version needed to query CVE databases for known unpatched exploits."
                      defenseTip="Suppress server tokens in your reverse proxy config (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx)."
                    />
                  </div>
                </div>
                <div className="flex-1 font-mono text-slate-300">
                  {data.securityHeaders?.headers?.serverHeader || data.securityHeaders?.headers?.poweredBy ? (
                    <span className="text-amber-300">
                      Exposing: {data.securityHeaders.headers.serverHeader || data.securityHeaders.headers.poweredBy}
                    </span>
                  ) : (
                    <span className="text-emerald-400">Server banner stripped or obfuscated.</span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
