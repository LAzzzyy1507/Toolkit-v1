import React, { useState } from 'react';
import { Terminal, Shield, Network, HardDrive, AlertTriangle, CheckCircle2, Copy, Check, ExternalLink } from 'lucide-react';
import { Explainer } from '../Explainer.tsx';

export const HomeLabGuide: React.FC = () => {
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">Practice at Home: Isolated Security Lab Walkthrough</h2>
            <Explainer
              term="Isolated Lab"
              title="Virtual Isolated Sandbox Architecture"
              summary="An offline, host-only virtual network containing intentionally vulnerable operating systems and test servers."
              whyItMatters="Hands-on practice is essential for building defensive instincts, but testing security tools against systems without explicit permission is illegal. An isolated VM sandbox guarantees zero collateral damage."
              defenseTip="Always verify that your hypervisor network adapter is set to 'Host-Only' or 'Internal Network' rather than 'Bridged' so vulnerable VMs are invisible to your physical home Wi-Fi."
            />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Build a risk-free, safe virtualized training sandbox on your personal laptop using VirtualBox and intentionally vulnerable target machines.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
          <Shield className="w-4 h-4" />
          <span>100% Legal & Safe Practice</span>
        </div>
      </div>

      {/* Safety Warning Card */}
      <div className="p-4 bg-amber-950/30 border border-amber-800/80 rounded-xl space-y-2 text-xs text-amber-200">
        <div className="flex items-center gap-2 font-bold text-sm">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <span>Golden Rule of Security Practice: Strict Network Isolation</span>
        </div>
        <p className="text-slate-300 leading-relaxed">
          Intentionally vulnerable VMs (like Metasploitable or DVWA) contain known critical root-level remote code execution exploits. Never configure these machines with a <strong>Bridged Adapter</strong> or expose them to the public internet. Use <strong>Host-Only Networking</strong> so only your local host machine and the target VM can communicate over a private subnet (e.g. <code className="text-cyan-300 font-mono">192.168.56.0/24</code>).
        </p>
      </div>

      {/* Step by Step Guide */}
      <div className="space-y-6">
        {/* Step 1 */}
        <div className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 flex items-center justify-center font-mono text-xs font-bold text-cyan-400">
                1
              </span>
              <h3 className="text-sm font-bold text-white">Install a Type-2 Hypervisor</h3>
            </div>
            <span className="text-xs text-slate-400 font-mono">Free & Open Source</span>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">
            A hypervisor allows your computer to run multiple isolated virtual machines (VMs) without affecting your primary operating system.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-1">
              <span className="font-bold text-slate-200 block">Oracle VirtualBox (Recommended)</span>
              <p className="text-slate-400">Works across Windows, macOS (Intel & Apple Silicon), and Linux. Fully free.</p>
              <a
                href="https://www.virtualbox.org/"
                target="_blank"
                rel="noreferrer"
                className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 text-[11px] pt-1"
              >
                Download VirtualBox <ExternalLink className="w-3 h-3" />
              </a>
            </div>

            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-1">
              <span className="font-bold text-slate-200 block">VMware Workstation Player</span>
              <p className="text-slate-400">High performance on Windows/Linux; free for personal educational use.</p>
              <a
                href="https://www.vmware.com/"
                target="_blank"
                rel="noreferrer"
                className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 text-[11px] pt-1"
              >
                Download VMware <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        </div>

        {/* Step 2 */}
        <div className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 flex items-center justify-center font-mono text-xs font-bold text-cyan-400">
                2
              </span>
              <h3 className="text-sm font-bold text-white">Configure the Isolated Host-Only Network</h3>
            </div>
            <span className="text-xs text-slate-400 font-mono">Zero WAN Exposure</span>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">
            In VirtualBox, open <strong>Tools → Network Manager</strong> and ensure a <strong>Host-only Network</strong> (e.g. <code className="text-cyan-300 font-mono">vboxnet0</code>) is configured. This allocates an IP range like <code className="text-cyan-300 font-mono">192.168.56.x</code> that exists exclusively in software on your laptop.
          </p>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs text-slate-300 space-y-1">
            <div className="text-slate-400"># VM Network Settings Checklist:</div>
            <div>Adapter 1: Attached to: <span className="text-cyan-400">Host-only Adapter</span></div>
            <div>Name: <span className="text-cyan-400">VirtualBox Host-Only Ethernet Adapter</span></div>
            <div>Promiscuous Mode: <span className="text-emerald-400">Allow All</span> (for packet sniffing experiments)</div>
          </div>
        </div>

        {/* Step 3 */}
        <div className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 flex items-center justify-center font-mono text-xs font-bold text-cyan-400">
                3
              </span>
              <h3 className="text-sm font-bold text-white">Download Intentionally Vulnerable Targets</h3>
            </div>
            <span className="text-xs text-slate-400 font-mono">Official Training Machines</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-1.5">
              <span className="font-bold text-slate-200 block">Metasploitable 2</span>
              <p className="text-slate-400 leading-relaxed">
                Classic Linux VM configured with dozens of vulnerable services: unencrypted FTP (port 21), Telnet (port 23), vulnerable Samba, and unpatched databases.
              </p>
              <a
                href="https://sourceforge.net/projects/metasploitable/"
                target="_blank"
                rel="noreferrer"
                className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 text-[11px] pt-1"
              >
                SourceForge VM Image <ExternalLink className="w-3 h-3" />
              </a>
            </div>

            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-1.5">
              <span className="font-bold text-slate-200 block">OWASP Juice Shop</span>
              <p className="text-slate-400 leading-relaxed">
                Modern, realistic insecure e-commerce web application covering the entire OWASP Top 10: SQL injection, broken access control, XSS, and JWT flaws.
              </p>
              <a
                href="https://owasp.org/www-project-juice-shop/"
                target="_blank"
                rel="noreferrer"
                className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 text-[11px] pt-1"
              >
                OWASP Juice Shop <ExternalLink className="w-3 h-3" />
              </a>
            </div>

            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 space-y-1.5">
              <span className="font-bold text-slate-200 block">Damn Vulnerable Web App (DVWA)</span>
              <p className="text-slate-400 leading-relaxed">
                PHP/MySQL web app with adjustable difficulty toggles (Low, Medium, High, Impossible) specifically designed to teach vulnerability mechanics.
              </p>
              <a
                href="https://github.com/digininja/DVWA"
                target="_blank"
                rel="noreferrer"
                className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 text-[11px] pt-1"
              >
                DVWA GitHub <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        </div>

        {/* Step 4 */}
        <div className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 flex items-center justify-center font-mono text-xs font-bold text-cyan-400">
                4
              </span>
              <h3 className="text-sm font-bold text-white">
                How CyberToolkit Directly Powers Your Lab Experiments
              </h3>
            </div>
            <span className="text-xs text-cyan-400 font-mono">App Integration</span>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">
            The tools in this web application were designed to work directly alongside your local training VM:
          </p>

          <div className="space-y-3 text-xs">
            <div className="p-3.5 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1.5">
              <span className="font-bold text-cyan-400 flex items-center gap-2">
                <span>Experiment A: Scan Your Local Metasploitable VM with CyberToolkit Port Scanner</span>
              </span>
              <p className="text-slate-300 leading-relaxed">
                Once Metasploitable boots, run <code className="text-slate-100 font-mono">ifconfig</code> inside the VM to find its host-only IP (e.g. <code className="text-cyan-300 font-mono">192.168.56.101</code>). Enter that IP into CyberToolkit's <strong>Port Scanner</strong>. You will observe ports 21 (FTP), 22 (SSH), 25 (SMTP), 80 (HTTP), 445 (SMB), and 3306 (MySQL) in the <span className="text-emerald-400 font-bold">OPEN</span> state.
              </p>
            </div>

            <div className="p-3.5 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1.5">
              <span className="font-bold text-cyan-400 flex items-center gap-2">
                <span>Experiment B: Capture & Inspect Plaintext Traffic in the Packet Analyzer</span>
              </span>
              <p className="text-slate-300 leading-relaxed">
                Open Wireshark on your host machine and capture 10 seconds on your Host-Only adapter. In your browser, browse to <code className="text-cyan-300 font-mono">http://192.168.56.101/dvwa/login.php</code> and type a test username and password. Stop the capture, save as <code className="text-slate-100 font-mono">mylab.pcap</code>, and upload it into CyberToolkit's <strong>Packet Capture Analyzer</strong>. You will see CyberToolkit automatically reconstruct the HTTP conversation and flag the cleartext password in the security findings table!
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
