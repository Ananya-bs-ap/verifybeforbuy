/**
 * Top Navigation Bar
 * Follows the 3-zone Top Bar Contract:
 * [Brand wordmark] — [Nav links] — [1 primary action]
 */

import React, { useState } from 'react';
import { Shield, Menu, X, Globe, Package, QrCode, History, HelpCircle, Info } from 'lucide-react';

export type NavTab =
  | 'home'
  | 'website'
  | 'product'
  | 'scanner'
  | 'history'
  | 'how-it-works'
  | 'about';

interface NavbarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, onSelectTab }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems: { id: NavTab; label: string; icon: React.ReactNode }[] = [
    { id: 'home', label: 'Home', icon: <Shield className="w-4 h-4" /> },
    { id: 'website', label: 'Website Checker', icon: <Globe className="w-4 h-4" /> },
    { id: 'product', label: 'Product Checker', icon: <Package className="w-4 h-4" /> },
    { id: 'scanner', label: 'Barcode Scanner', icon: <QrCode className="w-4 h-4" /> },
    { id: 'history', label: 'Scan History', icon: <History className="w-4 h-4" /> },
    { id: 'how-it-works', label: 'How It Works', icon: <HelpCircle className="w-4 h-4" /> },
    { id: 'about', label: 'About', icon: <Info className="w-4 h-4" /> },
  ];

  const handleNavClick = (tab: NavTab) => {
    onSelectTab(tab);
    setMobileMenuOpen(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <header className="sticky top-0 z-50 bg-slate-950/90 backdrop-blur-md border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between gap-8 h-16">
          {/* Zone 1: Single element brand wordmark */}
          <button
            onClick={() => handleNavClick('home')}
            className="flex items-center gap-2.5 text-lg font-bold tracking-tight text-white hover:text-teal-300 transition-colors whitespace-nowrap shrink-0 text-left"
          >
            <div className="w-8 h-8 rounded-lg bg-teal-500/10 border border-teal-500/30 flex items-center justify-center text-teal-400">
              <Shield className="w-5 h-5 fill-teal-400/20" />
            </div>
            <span>VerifyBeforeBuy AI</span>
          </button>

          {/* Zone 2: Clean single-line text navigation links */}
          <nav className="hidden lg:flex items-center gap-6 text-sm font-medium text-slate-400">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.id)}
                  className={`transition-colors whitespace-nowrap shrink-0 py-1 border-b-2 ${
                    isActive
                      ? 'text-teal-400 border-teal-400 font-semibold'
                      : 'border-transparent hover:text-slate-200'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Zone 3: 1 Primary Action */}
          <div className="hidden sm:flex items-center gap-3 shrink-0">
            <button
              onClick={() => handleNavClick('website')}
              className="px-4 py-2 text-xs font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-lg transition-colors whitespace-nowrap shrink-0 shadow-sm"
            >
              Check a Website
            </button>
          </div>

          {/* Mobile Menu Trigger */}
          <div className="lg:hidden flex items-center">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 text-slate-400 hover:text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-500"
              aria-label="Toggle Navigation Menu"
            >
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="lg:hidden border-b border-slate-800 bg-slate-950 px-4 pt-2 pb-6 space-y-2">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-left transition-colors ${
                  isActive
                    ? 'bg-teal-950/60 text-teal-300 border border-teal-800/60'
                    : 'text-slate-300 hover:bg-slate-900 hover:text-white'
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
              </button>
            );
          })}
          <div className="pt-3">
            <button
              onClick={() => handleNavClick('website')}
              className="w-full py-2.5 text-center text-xs font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-lg transition-colors shadow-sm"
            >
              Check a Website Now
            </button>
          </div>
        </div>
      )}
    </header>
  );
};
