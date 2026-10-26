/**
 * VerifyBeforeBuy AI — Main Application Container
 * Complete routing and state orchestrator for all verification tools.
 */

import React, { useState } from 'react';
import { Navbar, NavTab } from './components/Navbar';
import { HomePage } from './pages/HomePage';
import { WebsiteCheckerPage } from './pages/WebsiteCheckerPage';
import { ProductCheckerPage } from './pages/ProductCheckerPage';
import { BarcodeScannerPage } from './pages/BarcodeScannerPage';
import { HistoryDashboardPage } from './pages/HistoryDashboardPage';
import { HowItWorksPage } from './pages/HowItWorksPage';
import { AboutPage } from './pages/AboutPage';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('home');

  const renderActiveView = () => {
    switch (activeTab) {
      case 'home':
        return <HomePage onNavigate={(tab) => setActiveTab(tab)} />;
      case 'website':
        return <WebsiteCheckerPage />;
      case 'product':
        return <ProductCheckerPage />;
      case 'scanner':
        return <BarcodeScannerPage />;
      case 'history':
        return <HistoryDashboardPage onNavigate={(tab) => setActiveTab(tab)} />;
      case 'how-it-works':
        return <HowItWorksPage />;
      case 'about':
        return <AboutPage onNavigate={(tab) => setActiveTab(tab)} />;
      default:
        return <HomePage onNavigate={(tab) => setActiveTab(tab)} />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-teal-500 selection:text-slate-950">
      {/* 3-zone Header Contract */}
      <Navbar activeTab={activeTab} onSelectTab={setActiveTab} />

      {/* Main Viewport Content */}
      <main className="flex-1">
        {renderActiveView()}
      </main>
    </div>
  );
}
