import React, { useState } from 'react';
import { Globe, Search, Server, MapPin, Database, Shield, ArrowRight, Loader2, AlertCircle } from 'lucide-react';
import { Explainer } from '../Explainer.tsx';

export const IpDomainIntel: React.FC = () => {
  const [target, setTarget] = useState('cloudflare.com');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<any>(null);

  const handleLookup = async (lookupTarget?: string) => {
    const query = lookupTarget || target;
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(`/api/ip-domain?target=${encodeURIComponent(query.trim())}`);
      const json = await resp.json();
      if (!resp.ok) {
        throw new Error(json.error || 'Failed to lookup target');
      }
      setData(json);
    } catch (err: any) {
      setError(err.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const quickSamples = ['cloudflare.com', 'google.com', 'github.com', '1.1.1.1'];

  return (
    <div className="space-y-6">
      {/* Header & Concept intro */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">IP & Domain Intelligence</h2>
            <Explainer
              term="OSINT"
              title="Open-Source Intelligence (OSINT) & Network Reconnaissance"
              summary="Network reconnaissance is the process of mapping out an organization's public infrastructure—such as authoritative nameservers, autonomous system numbers, and hosting providers—using publicly available protocols."
              whyItMatters="Both defensive security engineers and penetration testers begin assessments here to map out an organization's attack perimeter and identify misconfigured mail servers or cloud assets."
              defenseTip="Regularly audit your external DNS zone files to eliminate dangling DNS records (which prevent subdomain takeover attacks) and hide internal infrastructure topology."
            />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Resolve DNS records, investigate Autonomous System routing (ASN), geolocation, and RDAP registration data.
          </p>
        </div>

        {/* Quick sample pills */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-slate-400">Quick tests:</span>
          {quickSamples.map((sample) => (
            <button
              key={sample}
              type="button"
              onClick={() => {
                setTarget(sample);
                handleLookup(sample);
              }}
              className="px-2.5 py-1 text-xs text-slate-300 bg-slate-900 hover:bg-slate-800 hover:text-white border border-slate-700/60 rounded-md transition-colors font-mono cursor-pointer"
            >
              {sample}
            </button>
          ))}
        </div>
      </div>

      {/* Input query bar */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
            <Globe className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
            placeholder="Enter domain (e.g. example.com) or IP address..."
            className="w-full pl-9 pr-4 py-2.5 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
        <button
          type="button"
          onClick={() => handleLookup()}
          disabled={loading || !target.trim()}
          className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-400 text-white text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 cursor-pointer shrink-0"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          <span>Query Target</span>
        </button>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-lg flex items-start gap-3 text-rose-200 text-xs">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold block">Lookup Error</span>
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Results grid */}
      {data && (
        <div className="space-y-6">
          {/* Top metadata overview */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span>Queried Host</span>
                <Explainer
                  term="FQDN"
                  title="Fully Qualified Domain Name & IP Resolution"
                  summary="The canonical hostname submitted to recursive DNS resolvers to map human-readable names to numeric IP addresses."
                  whyItMatters="CDNs and reverse proxies use Anycast IP routing, meaning one domain resolves to different geographic server clusters depending on where you query it from."
                />
              </div>
              <div className="text-base font-mono font-semibold text-slate-100 truncate">{data.target}</div>
              <div className="text-xs text-slate-400 mt-1 font-mono">
                {data.isIp ? 'Raw IP Address Query' : `${data.resolvedIps?.length || 0} Resolved Address(es)`}
              </div>
            </div>

            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span>Network ASN & ISP</span>
                <Explainer
                  term="ASN"
                  title="Autonomous System Number (ASN) & BGP Routing"
                  summary="An Autonomous System is a collection of IP routing prefixes under the control of a single administrative entity (like Cloudflare, AWS, or an ISP) that presents a common routing policy to the Internet."
                  whyItMatters="Knowing which ASN an IP belongs to tells you who physically or logically controls the network infrastructure. Attackers often target hosting providers with lax abuse enforcement."
                  defenseTip="Cloud engineers use ASN whitelisting/blocking at Web Application Firewalls (WAF) to block traffic originating from known malicious bulletproof hosting ASNs."
                />
              </div>
              <div className="text-sm font-semibold text-slate-100 truncate">
                {data.geoData?.isp || 'Unknown ISP'}
              </div>
              <div className="text-xs text-cyan-400 font-mono mt-1 truncate">
                {data.geoData?.as || 'No ASN telemetry'}
              </div>
            </div>

            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span>Geolocation</span>
                <Explainer
                  term="GeoIP"
                  title="IP Geolocation Intelligence"
                  summary="Mapping of an IP address to the geographic location of the network edge server or internet gateway."
                  whyItMatters="Security Operations Centers (SOCs) use GeoIP to flag impossible travel alerts (e.g. an employee logging in from London then Singapore 10 minutes later) and geo-fencing."
                />
              </div>
              <div className="text-sm font-semibold text-slate-100 truncate">
                {data.geoData ? `${data.geoData.city || ''}, ${data.geoData.country || ''}` : 'Location unlisted'}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-1">
                {data.geoData?.timezone ? `Timezone: ${data.geoData.timezone}` : 'Global Anycast Route'}
              </div>
            </div>
          </div>

          {/* DNS Records Table */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-5 py-3.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-200">DNS Zone Records</h3>
              </div>
              <Explainer
                term="DNS"
                title="Domain Name System (DNS) Records"
                summary="DNS maps human names to network addresses. A records map to IPv4, AAAA to IPv6, MX handles mail server priority, and TXT holds domain verification strings."
                whyItMatters="Defenders inspect TXT records to verify SPF/DMARC email protections. Attackers inspect MX and TXT records to discover third-party SaaS tools linked to an organization."
                defenseTip="Always publish strict SPF (-all) and DMARC policies in TXT records to prevent email spoofing of your domain."
              />
            </div>

            <div className="divide-y divide-slate-800/80 text-xs">
              {/* A Records */}
              <div className="p-4 flex flex-col sm:flex-row sm:items-start gap-4">
                <div className="w-24 shrink-0 flex items-center gap-1 font-mono font-semibold text-cyan-400">
                  <span>A (IPv4)</span>
                  <Explainer
                    term="A Record"
                    summary="Address record that maps a domain name directly to a 32-bit IPv4 address."
                    whyItMatters="Primary target for Web Application Firewall (WAF) routing and origin IP discovery."
                  />
                </div>
                <div className="flex-1 space-y-1 font-mono text-slate-300">
                  {data.dnsRecords?.A?.length > 0 ? (
                    data.dnsRecords.A.map((ip: string, i: number) => (
                      <div key={i} className="flex items-center gap-2">
                        <span className="text-slate-100">{ip}</span>
                      </div>
                    ))
                  ) : (
                    <span className="text-slate-400 italic">No A records returned</span>
                  )}
                </div>
              </div>

              {/* AAAA Records */}
              <div className="p-4 flex flex-col sm:flex-row sm:items-start gap-4">
                <div className="w-24 shrink-0 flex items-center gap-1 font-mono font-semibold text-cyan-400">
                  <span>AAAA (IPv6)</span>
                  <Explainer
                    term="AAAA Record"
                    summary="Maps a domain to a 128-bit IPv6 address. Quad-A indicates modern IPv6 network adoption."
                    whyItMatters="Security teams often forget to apply firewall rules to IPv6 interfaces, creating accidental backdoors."
                  />
                </div>
                <div className="flex-1 space-y-1 font-mono text-slate-300 break-all">
                  {data.dnsRecords?.AAAA?.length > 0 ? (
                    data.dnsRecords.AAAA.map((ip: string, i: number) => (
                      <div key={i} className="text-slate-100">{ip}</div>
                    ))
                  ) : (
                    <span className="text-slate-400 italic">No AAAA (IPv6) records</span>
                  )}
                </div>
              </div>

              {/* MX Records */}
              <div className="p-4 flex flex-col sm:flex-row sm:items-start gap-4">
                <div className="w-24 shrink-0 flex items-center gap-1 font-mono font-semibold text-cyan-400">
                  <span>MX (Mail)</span>
                  <Explainer
                    term="MX Record"
                    summary="Mail Exchange records specify the mail servers responsible for accepting incoming email for the domain, with integer priority weights."
                    whyItMatters="Reveals which email gateway or filtering provider (e.g. Google Workspace, Microsoft 365, Proofpoint, Mimecast) protects the company's mailboxes."
                  />
                </div>
                <div className="flex-1 space-y-1 font-mono text-slate-300">
                  {data.dnsRecords?.MX?.length > 0 ? (
                    data.dnsRecords.MX.map((mx: any, i: number) => (
                      <div key={i} className="flex items-center justify-between gap-4">
                        <span className="text-slate-100">{mx.exchange}</span>
                        <span className="text-slate-400 text-[11px]">Priority: {mx.priority}</span>
                      </div>
                    ))
                  ) : (
                    <span className="text-slate-400 italic">No MX records</span>
                  )}
                </div>
              </div>

              {/* TXT Records */}
              <div className="p-4 flex flex-col sm:flex-row sm:items-start gap-4">
                <div className="w-24 shrink-0 flex items-center gap-1 font-mono font-semibold text-cyan-400">
                  <span>TXT</span>
                  <Explainer
                    term="TXT Record"
                    summary="Text records hold arbitrary machine-readable data, commonly used for SPF (Sender Policy Framework), DKIM, DMARC, and domain ownership verification."
                    whyItMatters="Security audits inspect TXT records to confirm whether email spoofing defenses are active or if legacy SaaS tokens were left uncleaned."
                  />
                </div>
                <div className="flex-1 space-y-1.5 font-mono text-slate-300 break-all">
                  {data.dnsRecords?.TXT?.length > 0 ? (
                    data.dnsRecords.TXT.map((txt: string, i: number) => (
                      <div key={i} className="p-2 bg-slate-950/60 rounded border border-slate-800 text-[11px] text-slate-300">
                        {txt}
                      </div>
                    ))
                  ) : (
                    <span className="text-slate-400 italic">No TXT records</span>
                  )}
                </div>
              </div>

              {/* NS Records */}
              <div className="p-4 flex flex-col sm:flex-row sm:items-start gap-4">
                <div className="w-24 shrink-0 flex items-center gap-1 font-mono font-semibold text-cyan-400">
                  <span>NS (Nameserver)</span>
                  <Explainer
                    term="NS Record"
                    summary="Delegates a DNS zone to use specific authoritative nameservers."
                    whyItMatters="If an authoritative nameserver registration expires, an attacker can register the abandoned nameserver domain and seize control of all DNS records for the victim (Subdomain / Domain Hijacking)."
                  />
                </div>
                <div className="flex-1 space-y-1 font-mono text-slate-300">
                  {data.dnsRecords?.NS?.length > 0 ? (
                    data.dnsRecords.NS.map((ns: string, i: number) => (
                      <div key={i} className="text-slate-100">{ns}</div>
                    ))
                  ) : (
                    <span className="text-slate-400 italic">No NS records</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* RDAP / Registration Section */}
          {data.rdapData && (
            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                  RDAP Registration Metadata
                </span>
                <Explainer
                  term="RDAP"
                  title="RDAP vs WHOIS Protocol"
                  summary="Registration Data Access Protocol (RDAP) is the modern RESTful replacement for port 43 WHOIS, providing standardized JSON data and standardized role lookups."
                  whyItMatters="Since GDPR regulations in 2018, personal registrar data is redacted by default. Defenders use registration dates to detect 'lookalike' domains registered within the last 48 hours."
                  defenseTip="Set up brand monitoring alerts for newly registered domains that mimic your organization's trademark."
                />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-slate-300 font-mono pt-1">
                <div>
                  <span className="text-slate-400">Object Handle:</span>{' '}
                  <span className="text-slate-200">{data.rdapData.handle || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-400">Domain Status:</span>{' '}
                  <span className="text-slate-200">
                    {Array.isArray(data.rdapData.status) ? data.rdapData.status.slice(0, 2).join(', ') : 'Active'}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
