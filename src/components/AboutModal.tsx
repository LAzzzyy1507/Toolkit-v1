import React from 'react';
import { X, ShieldCheck, Server, Database, Lock, Github, ExternalLink } from 'lucide-react';

interface AboutModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AboutModal: React.FC<AboutModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="about-project-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-xs"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl bg-slate-900 border border-slate-700/80 rounded-2xl p-6 shadow-2xl text-left space-y-5"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between pb-3 border-b border-slate-800">
          <div>
            <span className="text-xs uppercase tracking-wider text-cyan-400 font-mono font-medium">Portfolio Showcase</span>
            <h2 id="about-project-title" className="text-lg font-bold text-white mt-0.5">
              About CyberToolkit
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
            aria-label="Close dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Primary non-technical summary paragraph */}
        <div className="space-y-3 text-sm leading-relaxed text-slate-300">
          <p className="text-slate-200">
            <strong>CyberToolkit</strong> is an educational cybersecurity workbench created to demystify complex security concepts through interactive diagnostics and real-time network analysis. Designed for students, aspiring security engineers, and hiring managers alike, every tool explains the "why" alongside the "what"—turning raw DNS records, cryptographic certificates, and packet streams into immediate learning moments. To maintain complete privacy and accessibility, the entire application operates strictly statelessly with zero user tracking, zero logins, and in-memory processing.
          </p>

          <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl space-y-2 text-xs">
            <span className="text-cyan-400 font-bold block uppercase tracking-wider font-mono">
              Engineering Architecture Highlights:
            </span>
            <ul className="space-y-1.5 text-slate-300">
              <li className="flex items-start gap-2">
                <span className="text-cyan-400 font-mono">•</span>
                <span>
                  <strong>Full-Stack TypeScript:</strong> React 19 SPA with Tailwind CSS v4 on Vite, backed by Express Node.js.
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-400 font-mono">•</span>
                <span>
                  <strong>Pure In-Memory PCAP Parser:</strong> Custom zero-dependency binary buffer parser for .pcap and .pcapng captures without requiring root or external CLI binaries.
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-400 font-mono">•</span>
                <span>
                  <strong>Defense-Oriented Design:</strong> Built-in rate limiting, safe TCP connect probing, and client-side password entropy calculations ensuring zero credentials touch the wire.
                </span>
              </li>
            </ul>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
          <span className="text-xs text-slate-400 font-mono">
            Designed for Portfolio & Educational Use
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
