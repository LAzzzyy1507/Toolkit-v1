import React from 'react';
import { ShieldAlert, BookOpen, Info, Terminal } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onOpenAbout: () => void;
  onOpenSearch: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, onOpenAbout, onOpenSearch }) => {
  const navItems = [
    { id: 'tools', label: 'Security Tools' },
    { id: 'ai-security', label: 'AI & LLM Security' },
    { id: 'lab-guide', label: 'Home Lab Guide' },
    { id: 'news', label: 'Advisories & News' },
    { id: 'resources', label: 'Learning Paths' },
  ];

  return (
    <header className="sticky top-0 z-40 w-full bg-slate-950/90 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Zone 1: Single text element wordmark */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setActiveTab('tools')}
            className="flex items-center gap-2.5 text-left group focus:outline-none cursor-pointer"
          >
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800/80 flex items-center justify-center text-cyan-400 group-hover:border-cyan-600 transition-colors">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <span className="text-base font-bold tracking-tight text-white group-hover:text-cyan-400 transition-colors">
                CyberToolkit
              </span>
            </div>
          </button>
        </div>

        {/* Zone 2: 4-6 clean text navigation links */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`transition-colors whitespace-nowrap py-1 cursor-pointer ${
                activeTab === item.id
                  ? 'text-cyan-400 font-semibold border-b-2 border-cyan-400'
                  : 'hover:text-slate-200'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        {/* Zone 3: 1-2 primary actions (Search Overlay button & About) */}
        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={onOpenSearch}
            className="px-2.5 sm:px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors flex items-center gap-2 cursor-pointer font-sans"
            title="Press Cmd+K or Ctrl+K to search"
            aria-label="Open search command palette"
          >
            <span className="hidden sm:inline">Quick Jump</span>
            <kbd className="flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-mono text-cyan-400 bg-slate-950 border border-slate-700/80 rounded">
              <span>⌘</span>
              <span>K</span>
            </kbd>
          </button>

          <button
            type="button"
            onClick={onOpenAbout}
            className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 border border-slate-700/80 rounded-lg hover:bg-slate-800 hover:text-white transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
          >
            <Info className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">About</span>
          </button>
        </div>
      </div>

      {/* Mobile nav drawer */}
      <div className="md:hidden flex items-center overflow-x-auto px-4 py-2 border-t border-slate-800/80 bg-slate-950 gap-2 no-scrollbar text-xs">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`px-3 py-1 rounded-md whitespace-nowrap font-medium transition-colors ${
              activeTab === item.id
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-slate-200 bg-slate-900'
            }`}
          >
            {item.label}
          </button>
        ))}
      </div>
    </header>
  );
};
