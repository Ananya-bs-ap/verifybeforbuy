/**
 * VerifyBeforeBuy AI — Main Application Container
 * Redesigned with a vibrant, human-crafted warm SaaS theme.
 */

import React, { useEffect, useState } from 'react';
import {
  Shield,
  Globe,
  Package,
  QrCode,
  Menu,
  X,
  Sparkles,
  ArrowRight,
  Key,
  LogIn,
  LogOut,
  UserPlus,
  User as UserIcon,
} from 'lucide-react';
import { WebsiteCheckerPage } from './pages/WebsiteCheckerPage';
import { ProductCheckerPage } from './pages/ProductCheckerPage';
import { BarcodeScannerPage } from './pages/BarcodeScannerPage';
import { HistoryDashboardPage } from './pages/HistoryDashboardPage';
import { AboutPage } from './pages/AboutPage';
import { LoginPage, RegisterPage, UpdatePasswordModal } from './pages/AuthPages';
import { AuthUserProfile } from './types';
import { AuthService, detectPasswordRecoveryInUrl } from './lib/supabase/authService';

export type NavTab =
  | 'home'
  | 'website'
  | 'product'
  | 'scanner'
  | 'history'
  | 'about'
  | 'login'
  | 'register';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('home');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [showApiKeyModal, setShowApiKeyModal] = useState(false);
  const [authUser, setAuthUser] = useState<AuthUserProfile | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [showPasswordRecoveryModal, setShowPasswordRecoveryModal] = useState(() =>
    detectPasswordRecoveryInUrl()
  );

  useEffect(() => {
    let active = true;

    AuthService.getSessionProfile().then(({ user }) => {
      if (!active) return;
      setAuthUser(user);
      setAuthLoading(false);
    });

    const { unsubscribe } = AuthService.onAuthStateChange((event, user) => {
      if (!active) return;
      setAuthUser(user);
      setAuthLoading(false);
      if (event === 'PASSWORD_RECOVERY') {
        setShowPasswordRecoveryModal(true);
      }
      if (event === 'SIGNED_OUT') {
        setShowPasswordRecoveryModal(false);
      }
    });

    return () => {
      active = false;
      unsubscribe();
    };
  }, []);

  const handleLogout = async () => {
    await AuthService.signOut();
    setAuthUser(null);
    setShowPasswordRecoveryModal(false);
    setMobileMenuOpen(false);
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      {/* Navbar - Vibrant Human-Crafted SaaS Design */}
      <header className="sticky top-0 z-50 bg-white/90 backdrop-blur-md border-b border-slate-200/80 shadow-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-20">
            {/* Brand Logo */}
            <button
              onClick={() => setActiveTab('home')}
              className="flex items-center gap-3 text-left group"
            >
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 to-violet-600 flex items-center justify-center text-white shadow-md shadow-indigo-500/20 group-hover:scale-105 transition-transform">
                <Shield className="w-6 h-6 fill-white/20" />
              </div>
              <div>
                <span className="text-lg font-extrabold tracking-tight text-slate-900 block group-hover:text-indigo-600 transition-colors">
                  VerifyBeforeBuy <span className="text-indigo-600">AI</span>
                </span>
                <span className="text-[11px] font-medium text-slate-500 block">
                  Smart Consumer Risk Shield
                </span>
              </div>
            </button>

            {/* Nav Links */}
            <nav className="hidden lg:flex items-center gap-8 text-sm font-semibold text-slate-600">
              <button
                onClick={() => setActiveTab('home')}
                className={`transition-colors py-1 ${activeTab === 'home' ? 'text-indigo-600 font-bold border-b-2 border-indigo-600' : 'hover:text-slate-900'}`}
              >
                Home
              </button>
              <button
                onClick={() => setActiveTab('website')}
                className={`transition-colors py-1 ${activeTab === 'website' ? 'text-indigo-600 font-bold border-b-2 border-indigo-600' : 'hover:text-slate-900'}`}
              >
                Website Checker
              </button>
              <button
                onClick={() => setActiveTab('product')}
                className={`transition-colors py-1 ${activeTab === 'product' ? 'text-indigo-600 font-bold border-b-2 border-indigo-600' : 'hover:text-slate-900'}`}
              >
                Product Checker
              </button>
              <button
                onClick={() => setActiveTab('scanner')}
                className={`transition-colors py-1 ${activeTab === 'scanner' ? 'text-indigo-600 font-bold border-b-2 border-indigo-600' : 'hover:text-slate-900'}`}
              >
                Barcode Scanner
              </button>
              <button
                onClick={() => setActiveTab('history')}
                className={`transition-colors py-1 ${activeTab === 'history' ? 'text-indigo-600 font-bold border-b-2 border-indigo-600' : 'hover:text-slate-900'}`}
              >
                Scan History
              </button>
              <button
                onClick={() => setActiveTab('about')}
                className={`transition-colors py-1 ${activeTab === 'about' ? 'text-indigo-600 font-bold border-b-2 border-indigo-600' : 'hover:text-slate-900'}`}
              >
                About
              </button>
            </nav>

            {/* Right Actions: API Key Guide + Auth Profile / Sign In */}
            <div className="hidden sm:flex items-center gap-2.5">
              <button
                onClick={() => setShowApiKeyModal(true)}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 rounded-xl transition-colors"
                title="Gemini API Key Setup"
              >
                <Key className="w-3.5 h-3.5 text-indigo-600" />
                <span className="hidden xl:inline">Gemini API Key</span>
              </button>

              {authUser ? (
                <div className="flex items-center gap-2 pl-2 pr-1.5 py-1 bg-slate-50 border border-slate-200 rounded-xl">
                  <div className="w-7 h-7 rounded-lg bg-gradient-to-tr from-indigo-600 to-violet-600 text-white text-xs font-bold flex items-center justify-center shrink-0">
                    {(authUser.displayName || authUser.email || 'U').charAt(0).toUpperCase()}
                  </div>
                  <div className="hidden md:block leading-tight max-w-[140px] truncate pr-1">
                    <div className="text-xs font-bold text-slate-900 truncate">
                      {authUser.displayName}
                    </div>
                    <div className="text-[10px] text-slate-500 truncate">{authUser.email}</div>
                  </div>
                  <button
                    type="button"
                    onClick={handleLogout}
                    className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:text-rose-700 hover:bg-rose-50 rounded-lg transition-colors"
                    title="Sign Out"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Sign Out</span>
                  </button>
                </div>
              ) : (
                !authLoading && (
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setActiveTab('login')}
                      className={`flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-xl border transition-colors ${
                        activeTab === 'login'
                          ? 'text-indigo-700 bg-indigo-50 border-indigo-300'
                          : 'text-slate-700 bg-white hover:bg-slate-50 border-slate-200'
                      }`}
                    >
                      <LogIn className="w-3.5 h-3.5" />
                      <span>Sign In</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab('register')}
                      className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-700 hover:to-violet-700 rounded-xl shadow-xs transition-all"
                    >
                      <UserPlus className="w-3.5 h-3.5" />
                      <span>Register</span>
                    </button>
                  </div>
                )
              )}
            </div>

            {/* Mobile Toggle */}
            <div className="lg:hidden">
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="p-2 text-slate-600 hover:text-slate-900"
              >
                {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
            </div>
          </div>
        </div>

        {/* Mobile menu */}
        {mobileMenuOpen && (
          <div className="lg:hidden bg-white border-b border-slate-200 px-4 pt-2 pb-6 space-y-2">
            <button
              onClick={() => { setActiveTab('home'); setMobileMenuOpen(false); }}
              className="w-full text-left px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-indigo-50 rounded-lg"
            >
              Home
            </button>
            <button
              onClick={() => { setActiveTab('website'); setMobileMenuOpen(false); }}
              className="w-full text-left px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-indigo-50 rounded-lg"
            >
              Website Checker
            </button>
            <button
              onClick={() => { setActiveTab('product'); setMobileMenuOpen(false); }}
              className="w-full text-left px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-indigo-50 rounded-lg"
            >
              Product Checker
            </button>
            <button
              onClick={() => { setActiveTab('scanner'); setMobileMenuOpen(false); }}
              className="w-full text-left px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-indigo-50 rounded-lg"
            >
              Barcode Scanner
            </button>
            <button
              onClick={() => { setActiveTab('history'); setMobileMenuOpen(false); }}
              className="w-full text-left px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-indigo-50 rounded-lg"
            >
              Scan History
            </button>
            <button
              onClick={() => { setActiveTab('about'); setMobileMenuOpen(false); }}
              className="w-full text-left px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-indigo-50 rounded-lg"
            >
              About
            </button>
            <button
              onClick={() => { setShowApiKeyModal(true); setMobileMenuOpen(false); }}
              className="w-full text-left px-3 py-2 text-sm font-semibold text-indigo-600 hover:bg-indigo-50 rounded-lg flex items-center gap-2"
            >
              <Key className="w-4 h-4" />
              <span>Gemini API Key Guide</span>
            </button>

            <div className="pt-2 border-t border-slate-100 space-y-2">
              {authUser ? (
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className="w-8 h-8 rounded-lg bg-indigo-600 text-white text-xs font-bold flex items-center justify-center shrink-0">
                      <UserIcon className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-bold text-slate-900 truncate">
                        {authUser.displayName}
                      </div>
                      <div className="text-[11px] text-slate-500 truncate">{authUser.email}</div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={handleLogout}
                    className="px-3 py-1.5 text-xs font-semibold text-rose-700 bg-rose-50 border border-rose-200 rounded-lg shrink-0"
                  >
                    Sign Out
                  </button>
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => { setActiveTab('login'); setMobileMenuOpen(false); }}
                    className="px-3 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-xl flex items-center justify-center gap-1.5"
                  >
                    <LogIn className="w-3.5 h-3.5" />
                    <span>Sign In</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => { setActiveTab('register'); setMobileMenuOpen(false); }}
                    className="px-3 py-2 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-violet-600 rounded-xl flex items-center justify-center gap-1.5"
                  >
                    <UserPlus className="w-3.5 h-3.5" />
                    <span>Register</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="flex-1">
        {activeTab === 'home' && (
          <div className="space-y-20 pb-20">
            {/* Hero Section with Vibrant Warm Gradient & Action Cards */}
            <section className="relative pt-16 pb-20 overflow-hidden bg-gradient-to-b from-indigo-50/70 via-white to-slate-50 border-b border-slate-200/60">
              <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center space-y-8">
                <div className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-bold text-indigo-700 bg-indigo-100/80 rounded-full border border-indigo-200 shadow-xs">
                  <Sparkles className="w-3.5 h-3.5 text-indigo-600" />
                  <span>AI-Assisted Shopping Risk &amp; Phishing Shield</span>
                </div>

                <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-slate-900 tracking-tight leading-[1.15]" style={{ textWrap: 'balance' }}>
                  Check the Risk. <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-600 to-violet-600">Shop with Confidence.</span>
                </h1>

                <p className="text-lg text-slate-600 max-w-2xl mx-auto leading-relaxed">
                  Evaluate potential phishing websites, deceptive storefronts, seller anomalies, and product pricing indicators before you pay.
                </p>

                {/* Primary Tool Action Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 max-w-3xl mx-auto pt-2 text-left">
                  <div className="bg-white p-6 sm:p-7 rounded-2xl border border-slate-200/80 shadow-xl shadow-indigo-500/10 hover:border-indigo-200 transition-all flex flex-col justify-between space-y-5 group">
                    <div className="space-y-3">
                      <div className="w-11 h-11 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center group-hover:scale-105 transition-transform">
                        <Globe className="w-5 h-5" />
                      </div>
                      <h2 className="text-lg font-bold text-slate-900">Website Checker</h2>
                      <p className="text-xs text-slate-600 leading-relaxed">
                        Inspect suspicious store URLs for phishing patterns, brand lookalikes, high-risk domains, and encryption status.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setActiveTab('website')}
                      className="w-full px-5 py-3 text-sm font-bold text-white bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-700 hover:to-violet-700 rounded-xl transition-all shadow-md shadow-indigo-500/20 flex items-center justify-center gap-2"
                    >
                      <span>Check Website</span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>

                  <div className="bg-white p-6 sm:p-7 rounded-2xl border border-slate-200/80 shadow-xl shadow-indigo-500/10 hover:border-violet-200 transition-all flex flex-col justify-between space-y-5 group">
                    <div className="space-y-3">
                      <div className="w-11 h-11 rounded-xl bg-violet-50 text-violet-600 flex items-center justify-center group-hover:scale-105 transition-transform">
                        <Package className="w-5 h-5" />
                      </div>
                      <h2 className="text-lg font-bold text-slate-900">Product Checker</h2>
                      <p className="text-xs text-slate-600 leading-relaxed">
                        Evaluate suspicious product listings for unusual pricing gaps, seller accountability, return terms, and red-flag phrasing.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setActiveTab('product')}
                      className="w-full px-5 py-3 text-sm font-bold text-white bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-700 hover:to-indigo-700 rounded-xl transition-all shadow-md shadow-violet-500/20 flex items-center justify-center gap-2"
                    >
                      <span>Check Product</span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            </section>

            {/* Feature Highlights - Vibrant Human Design */}
            <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="text-center max-w-2xl mx-auto mb-12 space-y-3">
                <span className="text-xs font-bold uppercase tracking-wider text-indigo-600 bg-indigo-50 px-3 py-1 rounded-full border border-indigo-100">
                  Comprehensive Consumer Protection
                </span>
                <h2 className="text-3xl font-extrabold text-slate-900">
                  Everything You Need Before You Pay
                </h2>
                <p className="text-sm text-slate-600">
                  Designed with clarity and warmth to help you spot scams without technical complexity.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                <div className="bg-white p-8 rounded-2xl border border-slate-200/80 shadow-md shadow-slate-200/50 hover:shadow-xl hover:border-indigo-200 transition-all space-y-4 group">
                  <div className="w-12 h-12 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center font-bold text-lg group-hover:scale-110 transition-transform">
                    <Globe className="w-6 h-6" />
                  </div>
                  <h3 className="text-lg font-bold text-slate-900">Website &amp; Phishing Checker</h3>
                  <p className="text-xs text-slate-600 leading-relaxed">
                    Instantly inspects URLs for typosquatting, brand impersonation, high-abuse TLDs, and SSL encryption status.
                  </p>
                  <button
                    onClick={() => setActiveTab('website')}
                    className="text-xs font-bold text-indigo-600 hover:text-indigo-700 flex items-center gap-1 pt-2"
                  >
                    <span>Open Website Checker</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="bg-white p-8 rounded-2xl border border-slate-200/80 shadow-md shadow-slate-200/50 hover:shadow-xl hover:border-indigo-200 transition-all space-y-4 group">
                  <div className="w-12 h-12 rounded-xl bg-violet-50 text-violet-600 flex items-center justify-center font-bold text-lg group-hover:scale-110 transition-transform">
                    <Package className="w-6 h-6" />
                  </div>
                  <h3 className="text-lg font-bold text-slate-900">Product &amp; Seller Assessor</h3>
                  <p className="text-xs text-slate-600 leading-relaxed">
                    Evaluates prices and seller background with fair anti-bias rules. Steep discounts are treated as reasons to check, not fraud.
                  </p>
                  <button
                    onClick={() => setActiveTab('product')}
                    className="text-xs font-bold text-indigo-600 hover:text-indigo-700 flex items-center gap-1 pt-2"
                  >
                    <span>Open Product Checker</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="bg-white p-8 rounded-2xl border border-slate-200/80 shadow-md shadow-slate-200/50 hover:shadow-xl hover:border-indigo-200 transition-all space-y-4 group">
                  <div className="w-12 h-12 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center font-bold text-lg group-hover:scale-110 transition-transform">
                    <QrCode className="w-6 h-6" />
                  </div>
                  <h3 className="text-lg font-bold text-slate-900">Barcode &amp; QR Scanner</h3>
                  <p className="text-xs text-slate-600 leading-relaxed">
                    Scans packaging barcodes using your camera with GS1 checksum validation and synthetic catalog matching.
                  </p>
                  <button
                    onClick={() => setActiveTab('scanner')}
                    className="text-xs font-bold text-indigo-600 hover:text-indigo-700 flex items-center gap-1 pt-2"
                  >
                    <span>Open Barcode Scanner</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </section>
          </div>
        )}

        {activeTab === 'website' && (
          <div className="py-8"><WebsiteCheckerPage /></div>
        )}

        {activeTab === 'product' && (
          <div className="py-8"><ProductCheckerPage /></div>
        )}

        {activeTab === 'scanner' && (
          <div className="py-8"><BarcodeScannerPage /></div>
        )}

        {activeTab === 'history' && (
          <div className="py-8">
            <HistoryDashboardPage
              authUser={authUser}
              onNavigate={(tab: any) => setActiveTab(tab)}
            />
          </div>
        )}

        {activeTab === 'about' && (
          <div className="py-8"><AboutPage onNavigate={(tab: any) => setActiveTab(tab)} /></div>
        )}

        {activeTab === 'login' && (
          <div className="py-8">
            <LoginPage
              onNavigate={(tab: any) => setActiveTab(tab)}
              onAuthSuccess={(user) => setAuthUser(user)}
            />
          </div>
        )}

        {activeTab === 'register' && (
          <div className="py-8">
            <RegisterPage
              onNavigate={(tab: any) => setActiveTab(tab)}
              onAuthSuccess={(user) => setAuthUser(user)}
            />
          </div>
        )}
      </main>

      {showPasswordRecoveryModal && (
        <UpdatePasswordModal
          onComplete={(updatedUser) => {
            if (updatedUser) setAuthUser(updatedUser);
            setShowPasswordRecoveryModal(false);
          }}
          onCancel={() => setShowPasswordRecoveryModal(false)}
        />
      )}

      {/* Gemini API Key Guide Modal */}
      {showApiKeyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
          <div className="bg-white border border-slate-200 rounded-2xl max-w-lg w-full p-6 sm:p-8 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center">
                  <Key className="w-4 h-4" />
                </div>
                <h3 className="font-extrabold text-slate-900 text-lg">Configuring Gemini AI Key</h3>
              </div>
              <button onClick={() => setShowApiKeyModal(false)} className="text-slate-400 hover:text-slate-700">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-600 leading-relaxed">
              <p>
                <strong>VerifyBeforeBuy AI</strong> uses Google Gemini 4 Hydrogen (<code>gemini-4-hydrogen</code>) for intelligent, plain-language risk explanations.
              </p>
              <div className="p-3.5 bg-indigo-50/70 border border-indigo-100 rounded-xl space-y-2">
                <strong className="text-indigo-950 block">How to provide your Gemini API Key:</strong>
                <ol className="list-decimal pl-4 space-y-1.5 text-indigo-900">
                  <li>In Google AI Studio, open the <strong>Settings &gt; Secrets</strong> panel.</li>
                  <li>Add your secret named <code>GEMINI_API_KEY</code>. AI Studio automatically injects it at runtime.</li>
                  <li>When deploying to Vercel or production, add <code>GEMINI_API_KEY</code> under your project&apos;s Environment Variables.</li>
                </ol>
              </div>
              <p className="text-[11px] text-slate-500">
                If no API key is provided, the application automatically uses robust built-in deterministic explanations with zero downtime.
              </p>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setShowApiKeyModal(false)}
                className="px-5 py-2.5 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl shadow-md transition-colors"
              >
                Got It, Thanks
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 py-12 text-slate-500 text-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2 font-extrabold text-slate-900 text-sm">
              <Shield className="w-4 h-4 text-indigo-600" />
              <span>VerifyBeforeBuy AI</span>
            </div>
            <div className="flex items-center gap-6 font-semibold">
              <button onClick={() => setActiveTab('home')} className="hover:text-indigo-600">Home</button>
              <button onClick={() => setActiveTab('website')} className="hover:text-indigo-600">Website Checker</button>
              <button onClick={() => setActiveTab('product')} className="hover:text-indigo-600">Product Checker</button>
              <button onClick={() => setActiveTab('scanner')} className="hover:text-indigo-600">Barcode Scanner</button>
              <button onClick={() => setActiveTab('about')} className="hover:text-indigo-600">About</button>
              <button onClick={() => setShowApiKeyModal(true)} className="hover:text-indigo-600">API Key Guide</button>
            </div>
          </div>
          <div className="pt-6 border-t border-slate-100 flex flex-col sm:flex-row items-center justify-between gap-4 text-slate-400 text-[11px]">
            <span>&copy; {new Date().getFullYear()} VerifyBeforeBuy AI. Open-access consumer protection platform.</span>
            <span>Preliminary risk assessment · Not physical proof of authenticity</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
