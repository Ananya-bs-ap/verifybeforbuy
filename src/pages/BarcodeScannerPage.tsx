/**
 * VerifyBeforeBuy AI — Barcode & QR Code Scanner Page
 * Camera-based scanner (html5-qrcode), image file drop scanner, manual code fallback,
 * GS1 modulo-10 checksum validation, demo catalog match, and safe payload inspection.
 */

import React, { useState, useEffect, useRef } from 'react';
import { Html5Qrcode } from 'html5-qrcode';
import {
  QrCode,
  Camera,
  Upload,
  Keyboard,
  AlertCircle,
  ShieldAlert,
  Loader2,
  StopCircle,
} from 'lucide-react';
import { AssessmentResult } from '../types';
import { ApiService } from '../lib/api';
import { HistoryService } from '../lib/supabase/historyService';
import { VerificationReport } from '../components/VerificationReport';
import { SYNTHETIC_DEMO_CATALOG } from '../lib/riskEngine/codeAnalyzer';

const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/jpg', 'image/png']);
const ALLOWED_EXTENSIONS = /\.(jpe?g|png)$/i;

export const BarcodeScannerPage: React.FC = () => {
  const [activeMode, setActiveMode] = useState<'camera' | 'upload' | 'manual'>('manual');
  const [manualCode, setManualCode] = useState('');
  const [isCameraActive, setIsCameraActive] = useState(false);
  const [cameraError, setCameraError] = useState<string | null>(null);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [currentResult, setCurrentResult] = useState<AssessmentResult | null>(null);

  const qrReaderRef = useRef<Html5Qrcode | null>(null);
  const isCameraActiveRef = useRef(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const readerElementId = 'vbb-qr-reader-container';

  const cleanupScannerResources = async () => {
    const instance = qrReaderRef.current;
    if (!instance) {
      isCameraActiveRef.current = false;
      setIsCameraActive(false);
      return;
    }

    try {
      if (isCameraActiveRef.current || instance.isScanning) {
        await instance.stop();
      }
    } catch (err) {
      console.warn('Error stopping scanner:', err);
    }

    try {
      instance.clear();
    } catch {
      // Container already clean or unmounted
    }

    qrReaderRef.current = null;
    isCameraActiveRef.current = false;
    setIsCameraActive(false);
  };

  // Cleanup camera & scanner resources on component unmount
  useEffect(() => {
    return () => {
      const instance = qrReaderRef.current;
      if (instance) {
        const stopPromise =
          isCameraActiveRef.current || instance.isScanning
            ? instance.stop().catch(() => {})
            : Promise.resolve();
        stopPromise.finally(() => {
          try {
            instance.clear();
          } catch {
            // Ignore unmount cleanup errors
          }
          qrReaderRef.current = null;
          isCameraActiveRef.current = false;
        });
      }
    };
  }, []);

  const handleModeChange = async (nextMode: 'camera' | 'upload' | 'manual') => {
    setCameraError(null);
    if (nextMode !== activeMode) {
      await cleanupScannerResources();
      setActiveMode(nextMode);
    }
  };

  const handleStartCamera = async () => {
    setCameraError(null);
    setIsLoading(true);

    try {
      await cleanupScannerResources();
      const html5QrCode = new Html5Qrcode(readerElementId, { verbose: false });
      qrReaderRef.current = html5QrCode;

      await html5QrCode.start(
        { facingMode: 'environment' },
        {
          fps: 10,
          qrbox: { width: 250, height: 250 },
        },
        async (decodedText, decodedResult) => {
          await cleanupScannerResources();
          handleAnalyzeCode(decodedText, decodedResult?.result?.format?.formatName || 'Camera Scan');
        },
        () => {
          // Frame callback - quiet
        }
      );

      isCameraActiveRef.current = true;
      setIsCameraActive(true);
    } catch (err: any) {
      console.warn('Camera start error:', err);
      await cleanupScannerResources();
      setCameraError(
        'Unable to access camera. Please verify camera permissions in your browser or use Image Upload / Manual Entry.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleStopCamera = async () => {
    await cleanupScannerResources();
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setCameraError(null);

    const mimeOk = !file.type || ALLOWED_MIME_TYPES.has(file.type.toLowerCase());
    const extOk = ALLOWED_EXTENSIONS.test(file.name);
    if (!mimeOk || !extOk) {
      setCurrentResult(null);
      setUploadedFileName(null);
      setCameraError('Unsupported file type. Please upload a JPG, JPEG, or PNG image containing a QR code or barcode.');
      e.target.value = '';
      return;
    }

    if (file.size === 0 || file.size > MAX_UPLOAD_BYTES) {
      setCurrentResult(null);
      setUploadedFileName(null);
      setCameraError(
        file.size === 0
          ? 'The selected image file is empty. Please choose a valid JPG, JPEG, or PNG image.'
          : 'Image exceeds the 5MB upload limit. Please choose a smaller JPG, JPEG, or PNG file.'
      );
      e.target.value = '';
      return;
    }

    setUploadedFileName(file.name);
    setIsLoading(true);

    let fileScanner: Html5Qrcode | null = null;
    try {
      await cleanupScannerResources();
      fileScanner = new Html5Qrcode(readerElementId, { verbose: false });
      qrReaderRef.current = fileScanner;

      const scanResult = await fileScanner.scanFileV2(file, false);
      const formatLabel = scanResult.result?.format?.formatName
        ? `Image Upload (${scanResult.result.format.formatName})`
        : 'Image File Scan';

      await handleAnalyzeCode(scanResult.decodedText, formatLabel);
    } catch (err: any) {
      console.warn('Image barcode/QR scan error:', err);
      setCurrentResult(null);
      setCameraError(
        'No readable QR code or 1D retail barcode was detected in this image. Ensure the code is sharp, well-lit, uncropped, or enter the digits manually.'
      );
    } finally {
      if (fileScanner) {
        try {
          fileScanner.clear();
        } catch {
          // Ignore clear failure
        }
        if (qrReaderRef.current === fileScanner) {
          qrReaderRef.current = null;
        }
      }
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      setIsLoading(false);
    }
  };

  const handleAnalyzeCode = async (codeToInspect: string, format?: string) => {
    const trimmed = codeToInspect.trim();
    if (!trimmed) {
      setCameraError('Please provide a barcode number or QR code text.');
      return;
    }

    setIsLoading(true);
    setCameraError(null);

    try {
      const result = await ApiService.analyzeCode({
        code: trimmed,
        format: format || 'Retail Code',
      });
      setCurrentResult(result);
      await HistoryService.saveRecord(result);
    } catch (err: any) {
      setCameraError(err.message || 'Code evaluation failed.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="space-y-3">
        <div className="inline-flex items-center gap-2 text-xs font-semibold text-teal-400 bg-teal-950/60 px-3 py-1 rounded-full border border-teal-800/60">
          <QrCode className="w-3.5 h-3.5" />
          <span>QR &amp; Barcode Risk Evaluator</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Scan Retail Codes &amp; Packaging QR
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl leading-relaxed">
          Inspect 1D retail barcodes (UPC-A, EAN-13) and QR redirects safely. Verify GS1 check digits, query live product registries (Open Food Facts, Open Beauty Facts, Open Products Facts, UPCitemdb), and screen QR links with our phishing ML detector.
        </p>
      </div>

      {/* Critical Consumer Warning Notice */}
      <div className="p-4 bg-slate-900/90 border border-amber-900/60 rounded-xl flex items-start gap-3 text-xs text-slate-300">
        <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <strong className="text-amber-300 block">Critical Authenticity Notice:</strong>
          <span>
            Scanning a barcode or QR code alone <strong>never proves</strong> a physical product is genuine. Counterfeiting operations routinely print authentic, copied barcodes onto replica packaging. Barcode scanning verifies numerical formatting and catalog alignment, not physical item authenticity.
          </span>
        </div>
      </div>

      {/* Mode Switcher */}
      <div className="flex items-center gap-2 p-1 bg-slate-900 border border-slate-800 rounded-xl w-fit">
        <button
          onClick={() => handleModeChange('manual')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg transition-colors ${
            activeMode === 'manual'
              ? 'bg-teal-400 text-slate-950 font-semibold shadow-sm'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Keyboard className="w-4 h-4" />
          <span>Manual Number Entry</span>
        </button>

        <button
          onClick={() => handleModeChange('camera')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg transition-colors ${
            activeMode === 'camera'
              ? 'bg-teal-400 text-slate-950 font-semibold shadow-sm'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Camera className="w-4 h-4" />
          <span>Camera Scanner</span>
        </button>

        <button
          onClick={() => handleModeChange('upload')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg transition-colors ${
            activeMode === 'upload'
              ? 'bg-teal-400 text-slate-950 font-semibold shadow-sm'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Upload className="w-4 h-4" />
          <span>Upload Image</span>
        </button>
      </div>

      {/* Scanner Interactive Container */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xl">
        {/* Persistent html5-qrcode mount so both live camera and image upload scanning always find #vbb-qr-reader-container */}
        <div
          id={readerElementId}
          className={`w-full max-w-md mx-auto rounded-xl overflow-hidden bg-slate-950 border border-slate-800 ${
            activeMode === 'camera' && isCameraActive ? 'min-h-[300px]' : 'hidden'
          }`}
        />

        {/* Mode A: Camera Scanner */}
        {activeMode === 'camera' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-white">Live Camera Inspection</h3>
                <p className="text-xs text-slate-400">Position the product barcode or QR code inside the viewfinder frame.</p>
              </div>

              {!isCameraActive ? (
                <button
                  onClick={handleStartCamera}
                  disabled={isLoading}
                  className="px-5 py-2.5 text-xs font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-xl transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  <Camera className="w-4 h-4" />
                  <span>{isLoading ? 'Requesting Permission...' : 'Activate Camera'}</span>
                </button>
              ) : (
                <button
                  onClick={handleStopCamera}
                  className="px-5 py-2.5 text-xs font-semibold text-rose-300 bg-rose-950/80 hover:bg-rose-900 border border-rose-800 rounded-xl transition-colors flex items-center justify-center gap-2"
                >
                  <StopCircle className="w-4 h-4" />
                  <span>Stop Camera</span>
                </button>
              )}
            </div>

            {!isCameraActive && (
              <div className="p-8 border border-dashed border-slate-800 rounded-xl text-center space-y-3 bg-slate-950/40">
                <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
                  <Camera className="w-6 h-6" />
                </div>
                <div className="text-xs text-slate-300 max-w-sm mx-auto">
                  Camera is currently off. Click &ldquo;Activate Camera&rdquo; to begin live scanning with environment focus.
                </div>
              </div>
            )}
          </div>
        )}

        {/* Mode B: Upload Image */}
        {activeMode === 'upload' && (
          <div className="space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Upload Barcode / QR Image</h3>
              <p className="text-xs text-slate-400">
                Select a clear JPG, JPEG, or PNG image of a product barcode (UPC/EAN/ITF/Code-128) or QR code.
              </p>
            </div>

            <label className="border-2 border-dashed border-slate-700 hover:border-teal-500 rounded-2xl p-8 flex flex-col items-center justify-center text-center cursor-pointer bg-slate-950/50 hover:bg-slate-950/80 transition-all space-y-3">
              {isLoading ? (
                <Loader2 className="w-8 h-8 text-teal-400 animate-spin" />
              ) : (
                <Upload className="w-8 h-8 text-teal-400" />
              )}
              <div className="text-xs text-slate-200">
                {isLoading ? (
                  <span className="font-semibold text-teal-300">
                    Decoding {uploadedFileName ? `"${uploadedFileName}"` : 'image'}...
                  </span>
                ) : (
                  <>
                    <span className="font-semibold text-teal-300">Click to upload</span> or choose an image file
                  </>
                )}
              </div>
              <span className="text-[11px] text-slate-500 font-mono">
                PNG, JPG, JPEG up to 5MB{uploadedFileName && !isLoading ? ` · Last file: ${uploadedFileName}` : ''}
              </span>
              <input
                ref={fileInputRef}
                type="file"
                accept=".jpg,.jpeg,.png,image/jpeg,image/png"
                onChange={handleFileUpload}
                disabled={isLoading}
                className="hidden"
              />
            </label>
          </div>
        )}

        {/* Mode C: Manual Code Input */}
        {activeMode === 'manual' && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleAnalyzeCode(manualCode);
            }}
            className="space-y-4"
          >
            <label htmlFor="manual-code-input" className="block text-xs font-semibold uppercase text-slate-300 tracking-wider">
              Barcode Digits (UPC / EAN) or QR Text / URL
            </label>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                id="manual-code-input"
                type="text"
                value={manualCode}
                onChange={(e) => setManualCode(e.target.value)}
                placeholder="e.g., 012000000133 (12 digits) or https://verify.brand.com"
                className="flex-1 px-4 py-3 bg-slate-950 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-teal-400 font-mono"
              />
              <button
                type="submit"
                disabled={isLoading}
                className="px-6 py-3 text-sm font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-xl transition-colors disabled:opacity-50 flex items-center justify-center gap-2 shrink-0 shadow-sm"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Evaluating...</span>
                  </>
                ) : (
                  <span>Inspect Code</span>
                )}
              </button>
            </div>
          </form>
        )}

        {cameraError && (
          <div className="p-3 bg-rose-950/60 border border-rose-900/60 rounded-lg text-xs text-rose-300 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{cameraError}</span>
          </div>
        )}

        {/* Demo Test Presets */}
        <div className="pt-4 border-t border-slate-800/80 space-y-3">
          <div className="text-xs text-slate-400 font-medium">
            Quick Test Barcodes (Live DB lookups run automatically for valid GS1 barcodes; synthetic demo records are used only as offline fallback):
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {Object.values(SYNTHETIC_DEMO_CATALOG).map((demo) => (
              <button
                key={demo.code}
                type="button"
                onClick={() => {
                  setManualCode(demo.code);
                  handleAnalyzeCode(demo.code, demo.format);
                }}
                className="p-3 bg-slate-950/60 hover:bg-slate-800/80 border border-slate-800 rounded-lg text-left transition-colors space-y-1 group"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-semibold text-teal-400 tabular-nums">
                    {demo.code}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">{demo.format}</span>
                </div>
                <div className="text-xs text-slate-300 truncate group-hover:text-white">
                  {demo.productName}
                </div>
                <div className="text-[11px] text-slate-400">
                  {demo.brand} · MSRP ${demo.suggestedRetailPrice}
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Assessment Report View */}
      {currentResult && (
        <div className="pt-4">
          <VerificationReport
            result={currentResult}
            onSave={(updated) => {
              void HistoryService.saveRecord(updated);
            }}
            onReset={() => {
              setCurrentResult(null);
              setManualCode('');
              setUploadedFileName(null);
              setCameraError(null);
            }}
          />
        </div>
      )}
    </div>
  );
};
