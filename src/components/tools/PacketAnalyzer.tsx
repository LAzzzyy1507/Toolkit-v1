import React, { useState } from 'react';
import { Upload, FileCode, AlertTriangle, ShieldAlert, CheckCircle2, Loader2, ArrowRightLeft, Radio, KeyRound } from 'lucide-react';
import { Explainer } from '../Explainer.tsx';
import { CopyButton } from '../CopyButton.tsx';

export const PacketAnalyzer: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<any>(null);
  const [selectedPacket, setSelectedPacket] = useState<any | null>(null);
  const [activeView, setActiveView] = useState<'packets' | 'findings' | 'conversations'>('findings');

  const formatPcapReport = () => {
    if (!analysis) return '';
    return [
      `# Packet Capture Analysis Report: ${analysis.filename}`,
      `Format: ${analysis.format} | Total Packets: ${analysis.totalPackets} | Volume: ${(analysis.totalBytes / 1024).toFixed(1)} KB`,
      `Capture Duration: ${analysis.durationSeconds}s`,
      `Protocols Observed: ${Object.entries(analysis.protocols || {}).map(([p, c]) => `${p}: ${c}`).join(', ')}`,
      `Plaintext Findings Count: ${analysis.plaintextWarningsCount}`,
      '',
      '--- Security Findings (Unencrypted / Cleartext Transmissions) ---',
      ...(analysis.findings && analysis.findings.length > 0
        ? analysis.findings.map((f: any) => [
            `[${f.type.toUpperCase()}] ${f.title}`,
            f.packetId ? `Packet #${f.packetId}` : '',
            `Description: ${f.description}`,
            f.details ? `Extracted Evidence: ${f.details}` : '',
            '----------------------------------------'
          ].filter(Boolean).join('\n'))
        : ['No unencrypted credentials or plain HTTP sessions detected.']),
      '',
      '--- Top Conversations ---',
      ...(analysis.conversations || []).slice(0, 10).map((c: any) =>
        `${c.endpointA} <-> ${c.endpointB} | Protocol: ${c.protocol} | Packets: ${c.packets} | ${(c.bytes / 1024).toFixed(1)} KB`
      )
    ].join('\n');
  };

  // Handle user uploading their own .pcap or .pcapng file
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng') && !file.name.endsWith('.cap')) {
      setError('Please upload a valid .pcap or .pcapng network capture file.');
      return;
    }

    setLoading(true);
    setError(null);

    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const base64Data = (reader.result as string).split(',')[1];
        const resp = await fetch('/api/pcap/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            filename: file.name,
            fileBase64: base64Data,
          }),
        });
        const data = await resp.json();
        if (!resp.ok) {
          throw new Error(data.error || 'Failed to analyze PCAP file.');
        }
        setAnalysis(data);
        if (data.findings && data.findings.length > 0) {
          setActiveView('findings');
        } else {
          setActiveView('packets');
        }
      } catch (err: any) {
        setError(err.message || 'PCAP processing failed');
      } finally {
        setLoading(false);
      }
    };
    reader.readAsDataURL(file);
  };

  // Handle loading demo scenarios
  const handleLoadDemo = async (demoType: 'auth_sniffing' | 'dns_recon') => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch('/api/pcap/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ demoType }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'Demo capture analysis failed.');
      }
      setAnalysis(data);
      if (demoType === 'auth_sniffing') {
        setActiveView('findings');
      } else {
        setActiveView('packets');
      }
    } catch (err: any) {
      setError(err.message || 'Demo loading failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">Packet Capture (PCAP) Analyzer</h2>
            <Explainer
              term="PCAP & Wire Sniffing"
              title="Packet Capture (PCAP) & Network Protocol Analysis"
              summary="Network interface cards in promiscuous mode record raw layer-2 and layer-3 Ethernet frames to disk. Files contain timestamps, headers, and full packet payloads."
              whyItMatters="Without TLS encryption, any intermediary device (compromised routers, rogue access points, ISP wiretaps) can reconstruct user sessions and extract passwords."
              defenseTip="Enforce end-to-end TLS 1.3 encryption across all internal services (Zero Trust mTLS) so packet captures reveal only encrypted ciphertext."
            />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Server-side in-memory parser. Reconstructs network flows and flags unencrypted cleartext passwords in transit.
          </p>
        </div>

        {/* Demo preset buttons */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-slate-400">Load sample capture:</span>
          <button
            type="button"
            onClick={() => handleLoadDemo('auth_sniffing')}
            className="px-2.5 py-1 text-xs text-cyan-300 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800 rounded-md transition-colors font-mono cursor-pointer"
          >
            Plaintext Auth Sniffing (.pcap)
          </button>
          <button
            type="button"
            onClick={() => handleLoadDemo('dns_recon')}
            className="px-2.5 py-1 text-xs text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-md transition-colors font-mono cursor-pointer"
          >
            DNS Reconnaissance (.pcap)
          </button>
        </div>
      </div>

      {/* Upload Zone */}
      <div className="p-6 bg-slate-900/60 border-2 border-dashed border-slate-800 hover:border-slate-700 rounded-xl text-center transition-colors">
        <input
          type="file"
          id="pcap-upload"
          accept=".pcap,.pcapng,.cap"
          onChange={handleFileUpload}
          className="hidden"
        />
        <label htmlFor="pcap-upload" className="cursor-pointer flex flex-col items-center gap-2">
          <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center text-cyan-400">
            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Upload className="w-5 h-5" />}
          </div>
          <span className="text-sm font-semibold text-slate-200">
            Click to upload your own .pcap or .pcapng capture
          </span>
          <span className="text-xs text-slate-400">
            In-memory stream processing only. Files are never written to disk or persisted.
          </span>
        </label>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-lg flex items-start gap-3 text-rose-200 text-xs">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold block">Parsing Issue</span>
            <span>{error}</span>
          </div>
        </div>
      )}

      {analysis && (
        <div className="space-y-6">
          <div className="flex items-center justify-between pb-1">
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 font-mono">
                Capture Analysis: <span className="text-slate-200">{analysis.filename}</span>
              </span>
            </div>
            <CopyButton
              text={formatPcapReport}
              label="Copy Packet Analysis"
              copiedLabel="Analysis Copied!"
            />
          </div>

          {/* Top Statistics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
              <span className="text-xs text-slate-400 block">Total Packets</span>
              <span className="text-2xl font-bold font-mono text-slate-100">{analysis.totalPackets}</span>
              <span className="text-[11px] text-slate-400 block font-mono mt-0.5">{analysis.format} format</span>
            </div>

            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
              <span className="text-xs text-slate-400 block">Volume & Duration</span>
              <span className="text-xl font-bold font-mono text-slate-100">
                {(analysis.totalBytes / 1024).toFixed(1)} KB
              </span>
              <span className="text-[11px] text-slate-400 block font-mono mt-0.5">{analysis.durationSeconds}s capture</span>
            </div>

            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
              <span className="text-xs text-slate-400 block">Protocols Observed</span>
              <div className="flex items-center gap-1.5 flex-wrap mt-1">
                {Object.entries(analysis.protocols || {}).map(([proto, count]: any) => (
                  <span
                    key={proto}
                    className="text-[11px] font-mono px-1.5 py-0.5 bg-slate-800 text-cyan-300 rounded"
                  >
                    {proto}: {count}
                  </span>
                ))}
              </div>
            </div>

            <div
              className={`p-4 rounded-xl border ${
                analysis.plaintextWarningsCount > 0
                  ? 'bg-rose-950/40 border-rose-800/80'
                  : 'bg-emerald-950/40 border-emerald-800/80'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400">Plaintext Findings</span>
                <Explainer
                  term="Wire Interception"
                  title="Plaintext Cleartext Vulnerabilities"
                  summary="When traffic is sent unencrypted over port 80 (HTTP) or 21 (FTP), attackers on the local LAN can read sensitive headers without cracking."
                  whyItMatters="Demonstrates why HTTPS, HSTS, and DNS over HTTPS (DoH) are non-negotiable security baselines."
                />
              </div>
              <span
                className={`text-2xl font-bold font-mono block ${
                  analysis.plaintextWarningsCount > 0 ? 'text-rose-400' : 'text-emerald-400'
                }`}
              >
                {analysis.plaintextWarningsCount} Warning(s)
              </span>
            </div>
          </div>

          {/* View switcher tabs */}
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setActiveView('findings')}
                className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer flex items-center gap-1.5 ${
                  activeView === 'findings'
                    ? 'bg-rose-950/80 text-rose-300 border border-rose-800'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Security Findings ({analysis.findings?.length || 0})</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveView('packets')}
                className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer flex items-center gap-1.5 ${
                  activeView === 'packets'
                    ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Radio className="w-3.5 h-3.5" />
                <span>Packet Stream ({analysis.packets?.length || 0})</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveView('conversations')}
                className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer flex items-center gap-1.5 ${
                  activeView === 'conversations'
                    ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <ArrowRightLeft className="w-3.5 h-3.5" />
                <span>Conversations ({analysis.conversations?.length || 0})</span>
              </button>
            </div>
          </div>

          {/* VIEW 1: Security Findings */}
          {activeView === 'findings' && (
            <div className="space-y-3">
              {analysis.findings && analysis.findings.length > 0 ? (
                analysis.findings.map((finding: any, i: number) => (
                  <div
                    key={i}
                    className="p-4 bg-rose-950/30 border border-rose-900/60 rounded-xl space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <KeyRound className="w-4 h-4 text-rose-400" />
                        <h4 className="font-bold text-rose-200 text-sm">{finding.title}</h4>
                      </div>
                      {finding.packetId && (
                        <span className="font-mono text-[11px] text-rose-400 bg-rose-950 px-2 py-0.5 rounded border border-rose-800">
                          Packet #{finding.packetId}
                        </span>
                      )}
                    </div>
                    <p className="text-slate-300 leading-relaxed">{finding.description}</p>
                    {finding.details && (
                      <div className="p-2.5 bg-slate-950 rounded border border-slate-800 font-mono text-[11px] text-amber-300 break-all">
                        {finding.details}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="p-8 text-center bg-slate-900/40 border border-slate-800 rounded-xl text-emerald-400 text-xs flex flex-col items-center gap-2">
                  <CheckCircle2 className="w-6 h-6" />
                  <span>No unencrypted cleartext passwords or insecure HTTP sessions were detected in this capture.</span>
                </div>
              )}
            </div>
          )}

          {/* VIEW 2: Packet List */}
          {activeView === 'packets' && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
              <div className="max-h-96 overflow-y-auto divide-y divide-slate-800/70 text-xs font-mono">
                {analysis.packets.map((pkt: any) => (
                  <div
                    key={pkt.id}
                    onClick={() => setSelectedPacket(pkt)}
                    className={`p-3 flex items-center justify-between hover:bg-slate-800/40 cursor-pointer transition-colors ${
                      pkt.isPlaintext ? 'bg-amber-950/20' : ''
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className="text-slate-400 w-8 shrink-0">{pkt.id}</span>
                      <span className="text-slate-400 w-16 shrink-0">{pkt.timestamp}</span>
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                          pkt.protocol === 'HTTP'
                            ? 'bg-amber-900/60 text-amber-300 border border-amber-800'
                            : pkt.protocol === 'TLS'
                            ? 'bg-emerald-900/60 text-emerald-300 border border-emerald-800'
                            : pkt.protocol === 'DNS'
                            ? 'bg-cyan-900/60 text-cyan-300 border border-cyan-800'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {pkt.protocol}
                      </span>
                      <span className="truncate text-slate-300">{pkt.info}</span>
                    </div>

                    <div className="flex items-center gap-3 shrink-0 text-slate-400 text-[11px]">
                      <span>{pkt.source} → {pkt.destination}</span>
                      <span className="text-slate-400">{pkt.length}B</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* VIEW 3: Conversations */}
          {activeView === 'conversations' && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
              <div className="divide-y divide-slate-800/70 text-xs font-mono">
                {analysis.conversations.map((conv: any, i: number) => (
                  <div key={i} className="p-3.5 flex items-center justify-between hover:bg-slate-800/30">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-100">{conv.endpointA}</span>
                      <ArrowRightLeft className="w-3.5 h-3.5 text-cyan-400" />
                      <span className="text-slate-100">{conv.endpointB}</span>
                    </div>
                    <div className="flex items-center gap-4 text-slate-400">
                      <span className="text-cyan-400 font-semibold">{conv.protocol}</span>
                      <span>{conv.packets} pkts</span>
                      <span>{(conv.bytes / 1024).toFixed(1)} KB</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Packet Details Drawer / Modal */}
          {selectedPacket && (
            <div
              className="p-4 bg-slate-900 border border-slate-700 rounded-xl space-y-3 text-xs"
              onClick={() => setSelectedPacket(null)}
            >
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-bold text-slate-200">
                  Packet #{selectedPacket.id} Detail View ({selectedPacket.protocol})
                </span>
                <span className="text-slate-400">Click anywhere to close</span>
              </div>
              <div className="grid grid-cols-2 gap-2 font-mono">
                <div>Source: <span className="text-slate-200">{selectedPacket.source}</span></div>
                <div>Destination: <span className="text-slate-200">{selectedPacket.destination}</span></div>
                <div>Length: <span className="text-slate-200">{selectedPacket.length} bytes</span></div>
                <div>Relative Time: <span className="text-slate-200">{selectedPacket.timestamp}</span></div>
              </div>
              {selectedPacket.plaintextSnippet && (
                <div className="space-y-1">
                  <span className="text-amber-400 font-semibold block">Decoded Payload Snippet:</span>
                  <pre className="p-2.5 bg-slate-950 rounded border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
                    {selectedPacket.plaintextSnippet}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
