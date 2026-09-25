import React, { useState } from 'react';
import { HelpCircle, X, ExternalLink } from 'lucide-react';

interface ExplainerProps {
  term: string;
  title?: string;
  summary: string;
  whyItMatters: string;
  defenseTip?: string;
  referenceUrl?: string;
  inline?: boolean;
}

export const Explainer: React.FC<ExplainerProps> = ({
  term,
  title,
  summary,
  whyItMatters,
  defenseTip,
  referenceUrl,
  inline = false,
}) => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <>
      <button
        type="button"
        onClick={() => setIsOpen(true)}
        className={`group inline-flex items-center gap-1 text-slate-400 hover:text-cyan-400 transition-colors cursor-pointer text-xs font-medium focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400 rounded ${
          inline ? 'align-middle ml-1' : ''
        }`}
        title={`Learn about: ${title || term}`}
        aria-label={`Learn about ${title || term}`}
      >
        <HelpCircle className="w-3.5 h-3.5 text-slate-400 group-hover:text-cyan-400 transition-colors shrink-0" />
        <span className="sr-only">Explain {term}</span>
      </button>

      {isOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby={`explainer-title-${term}`}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-xs"
          onClick={() => setIsOpen(false)}
        >
          <div
            className="w-full max-w-lg bg-slate-900 border border-slate-700/80 rounded-xl p-5 shadow-2xl text-left"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800">
              <div>
                <span className="text-xs uppercase tracking-wider text-cyan-400 font-mono font-medium">Security Concept</span>
                <h3 id={`explainer-title-${term}`} className="text-base font-semibold text-slate-100 mt-0.5">
                  {title || term}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="p-1 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors"
                aria-label="Close explanation"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-3.5 space-y-3 text-sm leading-relaxed text-slate-300">
              <div>
                <span className="text-xs font-semibold text-slate-400 block mb-1">What It Is:</span>
                <p className="text-slate-200">{summary}</p>
              </div>

              <div>
                <span className="text-xs font-semibold text-amber-400/90 block mb-1">Why It Matters in Security:</span>
                <p className="text-slate-300">{whyItMatters}</p>
              </div>

              {defenseTip && (
                <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
                  <span className="text-xs font-semibold text-emerald-400 block mb-1">Defensive Takeaway:</span>
                  <p className="text-xs text-slate-300">{defenseTip}</p>
                </div>
              )}

              {referenceUrl && (
                <div className="pt-2 flex justify-end">
                  <a
                    href={referenceUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                  >
                    Official Specification / RFC <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              )}
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800 flex justify-end">
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
              >
                Got It
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
