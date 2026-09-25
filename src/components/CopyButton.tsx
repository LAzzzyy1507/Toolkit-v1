import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface CopyButtonProps {
  text: string | (() => string);
  label?: string;
  copiedLabel?: string;
  className?: string;
  title?: string;
  iconOnly?: boolean;
}

export const CopyButton: React.FC<CopyButtonProps> = ({
  text,
  label = 'Copy Report',
  copiedLabel = 'Copied!',
  className = '',
  title = 'Copy to clipboard',
  iconOnly = false,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const content = typeof text === 'function' ? text() : text;
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(content);
      } else {
        // Fallback for restricted iframe environments
        const textArea = document.createElement('textarea');
        textArea.value = content;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy to clipboard', err);
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={title}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-lg transition-colors cursor-pointer select-none ${
        copied
          ? 'bg-emerald-950/80 border border-emerald-700 text-emerald-300'
          : 'bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700/80'
      } ${className}`}
      aria-label={label}
    >
      {copied ? (
        <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
      ) : (
        <Copy className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-200 shrink-0" />
      )}
      {!iconOnly && <span>{copied ? copiedLabel : label}</span>}
    </button>
  );
};
