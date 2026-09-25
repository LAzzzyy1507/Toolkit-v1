import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, CheckCircle2, XCircle, AlertTriangle, Search, Loader2, Lock, Radio } from 'lucide-react';
import { Explainer } from '../Explainer.tsx';

export const PortScanner: React.FC = () => {
  const [host, setHost] = useState('scanme.nmap.org');
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<any>(null);

  const handleScan = async (testHost?: string) => {
    const target = testHost || host;
    if (!target.trim() || !authorized) return;

    setLoading(true);
    setError(null);
    try {
      const resp = await fetch('/api/port-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          host: target.trim(),
          authorized,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'Port scan request failed.');
      }
      setScanResult(data);
    } catch (err: any) {
      setError(err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const sampleTargets = [
    { label: 'Authorized Test Host (scanme.nmap.org)', host: 'scanme.nmap.org' },
    { label: 'Google Public DNS', host: 'dns.google' },
    { label: 'Cloudflare', host: 'one.one.one.one' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">Defensive Port Scanner</h2>
            <Explainer
              term="Port Scanning"
              title="TCP Port Scanning & The 3-Way Handshake"
              summary="TCP connect scanning initiates a standard 3-way handshake (SYN → SYN-ACK → ACK) to determine if a listening daemon is accepting connections on a given port."
              whyItMatters="Exposed ports reveal running network daemons. Defenders scan perimeter hosts to ensure administrative interfaces (SSH, RDP, MySQL) are not exposed to the public internet."
              defenseTip="Implement network perimeter firewalls and Cloud Security Groups that follow the principle of least privilege, default-deny all inbound traffic."
            />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Test TCP connect accessibility against fixed standard service ports. Gated by explicit ownership verification.
          </p>
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-slate-400">Authorized targets:</span>
          {sampleTargets.map((s) => (
            <button
              key={s.host}
              type="button"
              onClick={() => {
                setHost(s.host);
                if (authorized) handleScan(s.host);
              }}
              className="px-2.5 py-1 text-xs text-slate-300 bg-slate-900 hover:bg-slate-800 hover:text-white border border-slate-700/60 rounded-md transition-colors font-mono cursor-pointer"
            >
              {s.host}
            </button>
          ))}
        </div>
      </div>

      {/* Mandatory Authorization Gating Banner */}
      <div
        className={`p-4 rounded-xl border transition-colors ${
          authorized
            ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-200'
            : 'bg-amber-950/30 border-amber-800/80 text-amber-200'
        }`}
      >
        <div className="flex items-start gap-3">
          <input
            type="checkbox"
            id="auth-check"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="mt-1 w-4 h-4 rounded border-slate-700 text-cyan-600 focus:ring-0 cursor-pointer"
          />
          <div className="space-y-1">
            <label htmlFor="auth-check" className="text-xs font-bold block cursor-pointer select-none">
              I own this system or have explicit written authorization to test it.
            </label>
            <p className="text-[11px] leading-relaxed text-slate-300">
              Port scanning without authorization can trigger IDS/IPS alarms, violate terms of service, and be construed as hostile reconnaissance. This scanner runs safe TCP connect probes only against fixed standard ports.
            </p>
          </div>
        </div>
      </div>

      {/* Target input */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
            <Radio className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && authorized && handleScan()}
            placeholder="Target hostname or IP address (e.g. scanme.nmap.org)..."
            className="w-full pl-9 pr-4 py-2.5 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
        <button
          type="button"
          onClick={() => handleScan()}
          disabled={loading || !host.trim() || !authorized}
          className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-500 disabled:cursor-not-allowed text-white text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 cursor-pointer shrink-0"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          <span>Start Scan</span>
        </button>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-lg flex items-start gap-3 text-rose-200 text-xs">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold block">Scan Interrupted</span>
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* TCP Port States Explainer Banner */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2 text-xs">
        <div className="flex items-center justify-between">
          <span className="font-semibold text-slate-200 uppercase tracking-wider font-mono">
            How to Interpret Port States
          </span>
          <Explainer
            term="Port States"
            title="Open vs Closed vs Filtered Port States"
            summary="Open means the server actively completed the TCP handshake with SYN-ACK. Closed means the OS replied with a TCP RST (reset) packet indicating no service is listening. Filtered means a stateful firewall silently dropped the probe."
            whyItMatters="Security architects configure firewalls to DROP packets rather than REJECT them so potential attackers cannot even determine if the host exists."
            defenseTip="Configure Linux iptables / UFW with DROP rules to keep unapproved ports in the 'Filtered' state."
          />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-slate-300">
          <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800/80">
            <span className="text-emerald-400 font-bold block mb-1">OPEN</span>
            <span>Target sent SYN-ACK. An active service daemon is listening and accepting client connections.</span>
          </div>
          <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800/80">
            <span className="text-slate-400 font-bold block mb-1">CLOSED</span>
            <span>Target sent TCP RST. The host is reachable, but no application is listening on this port.</span>
          </div>
          <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800/80">
            <span className="text-amber-400 font-bold block mb-1">FILTERED</span>
            <span>No reply / packet dropped. A firewall, security group, or NAT router blocked the probe.</span>
          </div>
        </div>
      </div>

      {/* Results Table */}
      {scanResult && (
        <div className="space-y-4">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl text-xs font-mono">
              <span className="text-slate-400 block">Scanned Target</span>
              <span className="font-bold text-slate-100 truncate block mt-0.5">
                {scanResult.target} ({scanResult.targetIp})
              </span>
            </div>
            <div className="p-3 bg-emerald-950/30 border border-emerald-800/60 rounded-xl text-xs font-mono">
              <span className="text-emerald-400 font-semibold block">Open Ports</span>
              <span className="text-lg font-bold text-emerald-300 mt-0.5 block">{scanResult.summary?.open}</span>
            </div>
            <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl text-xs font-mono">
              <span className="text-slate-400 block">Closed Ports</span>
              <span className="text-lg font-bold text-slate-300 mt-0.5 block">{scanResult.summary?.closed}</span>
            </div>
            <div className="p-3 bg-amber-950/30 border border-amber-800/60 rounded-xl text-xs font-mono">
              <span className="text-amber-400 font-semibold block">Filtered Ports</span>
              <span className="text-lg font-bold text-amber-300 mt-0.5 block">{scanResult.summary?.filtered}</span>
            </div>
          </div>

          {/* Table */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
            <div className="divide-y divide-slate-800/70 text-xs font-mono">
              {scanResult.ports?.map((p: any) => (
                <div
                  key={p.port}
                  className={`p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                    p.state === 'open' ? 'bg-emerald-950/15' : ''
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={`w-20 text-center py-1 rounded text-[11px] font-bold uppercase border ${
                        p.state === 'open'
                          ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                          : p.state === 'filtered'
                          ? 'bg-amber-950/60 text-amber-300 border-amber-800'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      {p.state}
                    </span>

                    <div>
                      <span className="font-bold text-slate-100">
                        Port {p.port}/TCP — {p.service}
                      </span>
                    </div>
                  </div>

                  <div className="text-slate-400 text-xs font-sans max-w-md sm:text-right">
                    {p.risk}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
