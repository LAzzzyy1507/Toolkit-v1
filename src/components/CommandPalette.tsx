import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
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
  Newspaper,
  Compass,
  Info,
  ArrowRight,
  CornerDownLeft,
  X,
} from 'lucide-react';

export interface CommandItem {
  id: string;
  title: string;
  category: 'Tools' | 'AI Security' | 'Practice Lab' | 'Intelligence & News' | 'Resources';
  description: string;
  keywords: string[];
  icon: React.ComponentType<{ className?: string }>;
  onSelect: () => void;
}

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateTool: (toolId: string) => void;
  onNavigateTab: (tabId: string) => void;
  onOpenAbout: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onNavigateTool,
  onNavigateTab,
  onOpenAbout,
}) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const commands: CommandItem[] = [
    // 8 Core Tools
    {
      id: 'tool-ip-domain',
      title: 'IP & Domain Intel',
      category: 'Tools',
      description: 'DNS records (A, AAAA, MX, TXT), ASN/ISP, BGP routing & RDAP',
      keywords: ['ip', 'domain', 'dns', 'whois', 'rdap', 'asn', 'bgp', 'mx', 'txt', 'lookup', 'geolocation'],
      icon: Globe,
      onSelect: () => {
        onNavigateTool('ip-domain');
        onClose();
      },
    },
    {
      id: 'tool-cert-headers',
      title: 'Certificate & Security Header Inspector',
      category: 'Tools',
      description: 'TLS certificate expiration, cipher suites, and OWASP header grading (CSP, HSTS, XFO)',
      keywords: ['ssl', 'tls', 'certificate', 'headers', 'csp', 'hsts', 'xss', 'clickjacking', 'https', 'crypto'],
      icon: Lock,
      onSelect: () => {
        onNavigateTool('cert-headers');
        onClose();
      },
    },
    {
      id: 'tool-subdomains',
      title: 'Subdomain Finder',
      category: 'Tools',
      description: 'Passive Certificate Transparency (crt.sh) log analysis without active brute-forcing',
      keywords: ['subdomains', 'crt.sh', 'certificate transparency', 'ct logs', 'recon', 'passive', 'osint', 'shadow it'],
      icon: Network,
      onSelect: () => {
        onNavigateTool('subdomains');
        onClose();
      },
    },
    {
      id: 'tool-cve-lookup',
      title: 'CVE & Vulnerability Explorer',
      category: 'Tools',
      description: 'NIST NVD search sorted by CVSS v3.1 severity metrics with vector breakdowns',
      keywords: ['cve', 'nvd', 'vulnerability', 'cvss', 'exploit', 'log4shell', 'heartbleed', 'cwe', 'nist'],
      icon: AlertCircle,
      onSelect: () => {
        onNavigateTool('cve-lookup');
        onClose();
      },
    },
    {
      id: 'tool-hash-password',
      title: 'Hash & Password Security Lab',
      category: 'Tools',
      description: 'Hash format identifier (no cracking) and client-side Shannon entropy calculation',
      keywords: ['hash', 'password', 'entropy', 'md5', 'sha256', 'bcrypt', 'argon2', 'brute force', 'shannon', 'gpu'],
      icon: KeyRound,
      onSelect: () => {
        onNavigateTool('hash-password');
        onClose();
      },
    },
    {
      id: 'tool-url-safety',
      title: 'URL Safety & Threat Inspector',
      category: 'Tools',
      description: 'Lexical heuristics, punycode/homograph detection, and Google Safe Browsing reputation',
      keywords: ['url', 'phishing', 'safe browsing', 'punycode', 'homograph', 'reputation', 'malicious', 'scam'],
      icon: Link2,
      onSelect: () => {
        onNavigateTool('url-safety');
        onClose();
      },
    },
    {
      id: 'tool-pcap-analyzer',
      title: 'Packet Capture (PCAP) Analyzer',
      category: 'Tools',
      description: 'In-memory .pcap/.pcapng parser highlighting unencrypted credentials and protocol flows',
      keywords: ['pcap', 'pcapng', 'packet', 'wireshark', 'sniffing', 'cleartext', 'http', 'tcp', 'network', 'traffic'],
      icon: FileCode,
      onSelect: () => {
        onNavigateTool('pcap-analyzer');
        onClose();
      },
    },
    {
      id: 'tool-port-scanner',
      title: 'Defensive Port Scanner',
      category: 'Tools',
      description: 'Safe TCP connect scan across standard ports (21-8443) gated by authorization check',
      keywords: ['port', 'scanner', 'nmap', 'tcp', 'handshake', 'open', 'closed', 'filtered', 'firewall', 'syn'],
      icon: Radio,
      onSelect: () => {
        onNavigateTool('port-scanner');
        onClose();
      },
    },

    // AI & LLM Security Modules
    {
      id: 'ai-prompt-injection',
      title: 'Prompt Injection: Direct & Indirect Overrides',
      category: 'AI Security',
      description: 'Why the code/data boundary vanishes in large language models and defense patterns',
      keywords: ['ai', 'llm', 'prompt injection', 'indirect', 'jailbreak', 'owasp llm', 'tokens', 'guardrails'],
      icon: BookOpen,
      onSelect: () => {
        onNavigateTab('ai-security');
        onClose();
      },
    },
    {
      id: 'ai-supply-chain',
      title: 'Model Supply-Chain Risk & Deserialization',
      category: 'AI Security',
      description: 'Arbitrary code execution via Python pickle weights vs Safetensors format',
      keywords: ['ai', 'pickle', 'safetensors', 'pytorch', 'supply chain', 'huggingface', 'deserialization'],
      icon: BookOpen,
      onSelect: () => {
        onNavigateTab('ai-security');
        onClose();
      },
    },
    {
      id: 'ai-least-privilege',
      title: 'Least Agentic Privilege & Tool Calling Security',
      category: 'AI Security',
      description: 'Securing autonomous AI agents with tools, APIs, and memory to prevent confused deputies',
      keywords: ['agent', 'function calling', 'least privilege', 'tools', 'autonomous', 'api security'],
      icon: BookOpen,
      onSelect: () => {
        onNavigateTab('ai-security');
        onClose();
      },
    },

    // Practice at Home Lab
    {
      id: 'lab-setup',
      title: 'Practice Lab: VirtualBox & Isolated Sandbox Setup',
      category: 'Practice Lab',
      description: 'Step-by-step host-only virtual networking to safely practice without touching real LANs',
      keywords: ['lab', 'virtualbox', 'vmware', 'host-only', 'sandbox', 'metasploitable', 'dvwa', 'isolated'],
      icon: Terminal,
      onSelect: () => {
        onNavigateTab('lab-guide');
        onClose();
      },
    },

    // Threat News & Intelligence
    {
      id: 'news-cisa-kev',
      title: 'Active Cyber Advisories & CISA KEV Feed',
      category: 'Intelligence & News',
      description: 'Live feed of active exploited vulnerabilities, required actions, and CISA security alerts',
      keywords: ['news', 'cisa', 'kev', 'advisories', 'alerts', 'threat intel', 'zero day'],
      icon: Newspaper,
      onSelect: () => {
        onNavigateTab('news');
        onClose();
      },
    },

    // Learning Pathways
    {
      id: 'resources-tryhackme',
      title: 'Learning Pathways: TryHackMe & PortSwigger',
      category: 'Resources',
      description: 'Curated roadmaps for web security, Linux CLI, and transitioning toward Cloud Security',
      keywords: ['learning', 'tryhackme', 'hackthebox', 'portswigger', 'bandit', 'cloud security', 'career'],
      icon: Compass,
      onSelect: () => {
        onNavigateTab('resources');
        onClose();
      },
    },

    // Project Architecture
    {
      id: 'about-project',
      title: 'About CyberToolkit & Architecture',
      category: 'Resources',
      description: 'Non-technical project overview, stateless design, and educational philosophy',
      keywords: ['about', 'portfolio', 'stateless', 'architecture', 'readme', 'author'],
      icon: Info,
      onSelect: () => {
        onOpenAbout();
        onClose();
      },
    },
  ];

  // Filter commands by search query
  const filteredCommands = query.trim()
    ? commands.filter((cmd) => {
        const q = query.toLowerCase();
        return (
          cmd.title.toLowerCase().includes(q) ||
          cmd.description.toLowerCase().includes(q) ||
          cmd.category.toLowerCase().includes(q) ||
          cmd.keywords.some((k) => k.toLowerCase().includes(q))
        );
      })
    : commands;

  // Auto focus input when opened
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  // Keep selected index in bounds when results change
  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  // Keyboard navigation
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex((prev) => (prev < filteredCommands.length - 1 ? prev + 1 : 0));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex((prev) => (prev > 0 ? prev - 1 : filteredCommands.length - 1));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (filteredCommands[selectedIndex]) {
          filteredCommands[selectedIndex].onSelect();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, filteredCommands, selectedIndex, onClose]);

  // Scroll active item into view
  useEffect(() => {
    if (!listRef.current) return;
    const activeEl = listRef.current.querySelector(`[data-index="${selectedIndex}"]`);
    if (activeEl) {
      activeEl.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex]);

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Quick jump command palette"
      className="fixed inset-0 z-50 flex items-start justify-center pt-16 sm:pt-24 px-4 bg-slate-950/80 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl bg-slate-900 border border-slate-700/90 rounded-2xl shadow-2xl overflow-hidden flex flex-col text-left"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Bar */}
        <div className="flex items-center px-4 py-3.5 border-b border-slate-800 gap-3">
          <Search className="w-5 h-5 text-cyan-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a tool name, concept, or security topic (e.g. 'cve', 'pcap', 'prompt injection')..."
            className="w-full bg-transparent text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none font-sans"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery('')}
              className="p-1 text-slate-400 hover:text-slate-200 rounded"
              aria-label="Clear search"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          <kbd className="hidden sm:inline-block px-2 py-0.5 text-[11px] font-mono font-medium text-slate-400 bg-slate-800 border border-slate-700 rounded">
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div
          ref={listRef}
          className="max-h-96 overflow-y-auto p-2 divide-y divide-slate-800/40 divide-solid"
        >
          {filteredCommands.length > 0 ? (
            filteredCommands.map((cmd, index) => {
              const Icon = cmd.icon;
              const isSelected = index === selectedIndex;

              return (
                <div
                  key={cmd.id}
                  data-index={index}
                  onClick={cmd.onSelect}
                  onMouseEnter={() => setSelectedIndex(index)}
                  className={`p-3 rounded-xl flex items-center justify-between gap-3 cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-slate-800/90 border border-slate-700 text-white'
                      : 'hover:bg-slate-800/40 text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div
                      className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                        isSelected
                          ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold truncate leading-tight">
                          {cmd.title}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800/80 text-slate-400 border border-slate-700/60 shrink-0">
                          {cmd.category}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 line-clamp-1 mt-0.5">
                        {cmd.description}
                      </p>
                    </div>
                  </div>

                  <div className="shrink-0 flex items-center gap-1 text-slate-400">
                    {isSelected && (
                      <span className="flex items-center gap-1 text-[11px] font-mono text-cyan-400">
                        <span>Select</span>
                        <CornerDownLeft className="w-3.5 h-3.5" />
                      </span>
                    )}
                  </div>
                </div>
              );
            })
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs">
              No tools or modules matched "{query}". Try searching for terms like "dns", "ssl", "pcap", or "port".
            </div>
          )}
        </div>

        {/* Footer Navigation Hints */}
        <div className="px-4 py-2.5 bg-slate-950/70 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-400 font-mono">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1">
              <kbd className="px-1.5 py-0.5 bg-slate-800 border border-slate-700 rounded text-[10px]">↑</kbd>
              <kbd className="px-1.5 py-0.5 bg-slate-800 border border-slate-700 rounded text-[10px]">↓</kbd>
              <span>to navigate</span>
            </span>
            <span className="flex items-center gap-1">
              <kbd className="px-1.5 py-0.5 bg-slate-800 border border-slate-700 rounded text-[10px]">↵</kbd>
              <span>to jump</span>
            </span>
          </div>
          <span>{filteredCommands.length} destination(s)</span>
        </div>
      </div>
    </div>
  );
};
