/**
 * CyberToolkit — Defensive Security & Systems Analysis Workbench
 * @license Apache-2.0
 */

import React, { useState } from 'react';
import {
  Globe,
  Lock,
  Network,
  AlertCircle,
  KeyRound,
  Link2,
  FileCode,
  Radio,
  BookOpen,
  Terminal,
  ShieldCheck,
  Newspaper,
  Compass,
  Layers,
  ArrowRight,
} from 'lucide-react';

import { Navbar } from './components/Navbar.tsx';
import { AboutModal } from './components/AboutModal.tsx';
import { Explainer } from './components/Explainer.tsx';

// 8 Primary Tools
import { IpDomainIntel } from './components/tools/IpDomainIntel.tsx';
import { CertHeaderInspector } from './components/tools/CertHeaderInspector.tsx';
import { SubdomainFinder } from './components/tools/SubdomainFinder.tsx';
import { CveLookup } from './components/tools/CveLookup.tsx';
import { HashPasswordLab } from './components/tools/HashPasswordLab.tsx';
import { UrlSafetyCheck } from './components/tools/UrlSafetyCheck.tsx';
import { PacketAnalyzer } from './components/tools/PacketAnalyzer.tsx';
import { PortScanner } from './components/tools/PortScanner.tsx';

// Learning & Context Layer
import { CyberNews } from './components/learning/CyberNews.tsx';
import { AiSecurityArticles } from './components/learning/AiSecurityArticles.tsx';
import { HomeLabGuide } from './components/learning/HomeLabGuide.tsx';
import { LearningResources } from './components/learning/LearningResources.tsx';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('tools');
  const [activeToolId, setActiveToolId] = useState<string>('ip-domain');
  const [isAboutOpen, setIsAboutOpen] = useState<boolean>(false);

  const tools = [
    {
      id: 'ip-domain',
      title: 'IP & Domain Intel',
      shortDesc: 'DNS records, ASN routing, and RDAP registration',
      icon: Globe,
    },
    {
      id: 'cert-headers',
      title: 'Certificate & Headers',
      shortDesc: 'TLS validity, cipher suites, and HTTP security grading',
      icon: Lock,
    },
    {
      id: 'subdomains',
      title: 'Subdomain Finder',
      shortDesc: 'Passive Certificate Transparency (crt.sh) log analysis',
      icon: Network,
    },
    {
      id: 'cve-lookup',
      title: 'CVE Lookup',
      shortDesc: 'NIST NVD search sorted by CVSS v3.1 severity metrics',
      icon: AlertCircle,
    },
    {
      id: 'hash-password',
      title: 'Hash & Password Lab',
      shortDesc: 'Format identification (no cracking) and Shannon entropy',
      icon: KeyRound,
    },
    {
      id: 'url-safety',
      title: 'URL Safety Check',
      shortDesc: 'Heuristic phishing checks and Safe Browsing reputation',
      icon: Link2,
    },
    {
      id: 'pcap-analyzer',
      title: 'Packet Capture Analyzer',
      shortDesc: 'In-memory .pcap parser flagging cleartext credentials',
      icon: FileCode,
    },
    {
      id: 'port-scanner',
      title: 'Port Scanner',
      shortDesc: 'Safe TCP connect scan gated by explicit authorization',
      icon: Radio,
    },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Bar Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenAbout={() => setIsAboutOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 space-y-8">
        {/* Hero Banner with Recruiter / Student Context */}
        <section className="p-6 sm:p-8 bg-slate-900/50 border border-slate-800/80 rounded-2xl relative overflow-hidden">
          <div className="max-w-3xl space-y-3 relative z-10">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <span>Defensive Cybersecurity Engineering</span>
              <span aria-hidden="true">·</span>
              <span>Stateless Architecture</span>
              <span aria-hidden="true">·</span>
              <span>Zero-Login Learning</span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Defensive Security & Systems Analysis Workbench
            </h1>

            <p className="text-sm text-slate-300 leading-relaxed">
              Every tool and diagnostic is designed to teach as it inspects. Explore live DNS records, TLS certificates, passive certificate transparency logs, unencrypted packet streams, and emerging AI safety vectors without creating accounts or persisting personal data.
            </p>

            <div className="pt-2 flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400">
              <span className="flex items-center gap-1.5 text-slate-300">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>8 Defensive Tools</span>
              </span>
              <span className="flex items-center gap-1.5 text-slate-300">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>In-Memory Packet Parser</span>
              </span>
              <span className="flex items-center gap-1.5 text-slate-300">
                <BookOpen className="w-4 h-4 text-amber-400" />
                <span>OWASP & CISA Aligned</span>
              </span>
            </div>
          </div>
        </section>

        {/* TAB 1: SECURITY TOOLS */}
        {activeTab === 'tools' && (
          <section className="space-y-6">
            {/* Tool Selection Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              {tools.map((t) => {
                const Icon = t.icon;
                const isSelected = t.id === activeToolId;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setActiveToolId(t.id)}
                    className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between ${
                      isSelected
                        ? 'bg-slate-900 border-cyan-500 shadow-md text-white'
                        : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/80 hover:border-slate-700 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div
                        className={`w-7 h-7 rounded-lg flex items-center justify-center ${
                          isSelected ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        <Icon className="w-4 h-4" />
                      </div>
                      <span className="text-[10px] font-mono text-slate-400">
                        0{tools.findIndex((x) => x.id === t.id) + 1}
                      </span>
                    </div>

                    <div>
                      <h2 className="text-xs sm:text-sm font-bold truncate leading-tight">{t.title}</h2>
                      <p className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">{t.shortDesc}</p>
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Active Tool Viewport */}
            <div className="p-6 sm:p-8 bg-slate-900/40 border border-slate-800 rounded-2xl">
              {activeToolId === 'ip-domain' && <IpDomainIntel />}
              {activeToolId === 'cert-headers' && <CertHeaderInspector />}
              {activeToolId === 'subdomains' && <SubdomainFinder />}
              {activeToolId === 'cve-lookup' && <CveLookup />}
              {activeToolId === 'hash-password' && <HashPasswordLab />}
              {activeToolId === 'url-safety' && <UrlSafetyCheck />}
              {activeToolId === 'pcap-analyzer' && <PacketAnalyzer />}
              {activeToolId === 'port-scanner' && <PortScanner />}
            </div>
          </section>
        )}

        {/* TAB 2: AI & LLM SECURITY */}
        {activeTab === 'ai-security' && (
          <section className="space-y-6">
            <AiSecurityArticles />
          </section>
        )}

        {/* TAB 3: HOME LAB GUIDE */}
        {activeTab === 'lab-guide' && (
          <section className="space-y-6">
            <HomeLabGuide />
          </section>
        )}

        {/* TAB 4: THREAT ADVISORIES & NEWS */}
        {activeTab === 'news' && (
          <section className="space-y-6">
            <CyberNews />
          </section>
        )}

        {/* TAB 5: LEARNING PATHS & PLATFORMS */}
        {activeTab === 'resources' && (
          <section className="space-y-6">
            <LearningResources />
          </section>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-6 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-200">CyberToolkit</span>
            <span>—</span>
            <span>Educational Defensive Security & Systems Analysis</span>
          </div>

          <div className="flex items-center gap-4 text-[11px] font-mono">
            <span>Stateless</span>
            <span>·</span>
            <span>In-Memory Processing</span>
            <span>·</span>
            <span>Zero Tracking</span>
          </div>
        </div>
      </footer>

      {/* About Project Modal */}
      <AboutModal isOpen={isAboutOpen} onClose={() => setIsAboutOpen(false)} />
    </div>
  );
}
