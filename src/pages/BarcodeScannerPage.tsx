/**
 * VerifyBeforeBuy AI — Barcode & QR Code Scanner Page
 * Camera-based scanner (html5-qrcode), image file drop scanner, manual code fallback,
 * GS1 modulo-10 checksum validation, live barcode registry lookup, and safe payload inspection.
 */

import React, { useState, useEffect, useRef } from 'react';
import { Html5Qrcode, Html5QrcodeSupportedFormats } from 'html5-qrcode';
import {
  QrCode,
  Camera,
  Upload,
  Keyboard,
  AlertCircle,
  ShieldAlert,
  Loader2,
  StopCircle,
  RefreshCw,
} from 'lucide-react';
import { AssessmentResult } from '../types';
import { ApiService } from '../lib/api';
import { HistoryService } from '../lib/supabase/historyService';
import { VerificationReport } from '../components/VerificationReport';
import { SYNTHETIC_DEMO_CATALOG } from '../lib/riskEngine/codeAnalyzer';
import {
  CameraDeviceInfo,
  checkCameraEnvironment,
  classifyCameraError,
  computeResponsiveQrBox,
  pickPreferredCamera,
} from '../lib/cameraScannerHelper';

const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/jpg', 'image/png']);
const ALLOWED_EXTENSIONS = /\.(jpe?g|png)$/i;

const SUPPORTED_SCAN_FORMATS: Html5QrcodeSupportedFormats[] = [
  Html5QrcodeSupportedFormats.QR_CODE,
  Html5QrcodeSupportedFormats.UPC_A,
  Html5QrcodeSupportedFormats.UPC_E,
  Html5QrcodeSupportedFormats.EAN_13,
  Html5QrcodeSupportedFormats.EAN_8,
  Html5QrcodeSupportedFormats.ITF,
  Html5QrcodeSupportedFormats.CODE_128,
  Html5QrcodeSupportedFormats.CODE_39,
  Html5QrcodeSupportedFormats.CODABAR,
  Html5QrcodeSupportedFormats.DATA_MATRIX,
  Html5QrcodeSupportedFormats.AZTEC,
  Html5QrcodeSupportedFormats.PDF_417,
];

function waitForNextFrame(): Promise<void> {
  if (typeof window === 'undefined' || typeof window.requestAnimationFrame !== 'function') {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    window.requestAnimationFrame(() => resolve());
  });
}

function stopOrphanedVideoTracks(containerId: string) {
  if (typeof document === 'undefined') return;
  const container = document.getElementById(containerId);
  if (!container) return;
  const videos = container.querySelectorAll('video');
  videos.forEach((video) => {
    const stream = video.srcObject as MediaStream | null;
    if (stream && typeof stream.getTracks === 'function') {
      stream.getTracks().forEach((track) => {
        try {
          track.enabled = false;
          track.stop();
        } catch {
          // Ignore track stop failure
        }
      });
    }
    try {
      video.pause();
      video.srcObject = null;
    } catch {
      // Ignore video cleanup failure
    }
  });
}

export const BarcodeScannerPage: React.FC = () => {
  const [activeMode, setActiveMode] = useState<'camera' | 'upload' | 'manual'>('manual');
  const [manualCode, setManualCode] = useState('');
  const [isCameraActive, setIsCameraActive] = useState(false);
  const [isStartingCamera, setIsStartingCamera] = useState(false);
  const [cameraError, setCameraError] = useState<string | null>(null);
  const [availableCameras, setAvailableCameras] = useState<CameraDeviceInfo[]>([]);
  const [selectedCameraId, setSelectedCameraId] = useState<string>('');
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [currentResult, setCurrentResult] = useState<AssessmentResult | null>(null);

  const qrReaderRef = useRef<Html5Qrcode | null>(null);
  const isCameraActiveRef = useRef(false);
  const isMountedRef = useRef(true);
  const scanSessionIdRef = useRef(0);
  const isHandlingDecodeRef = useRef(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const readerElementId = 'vbb-qr-reader-container';

  const cleanupScannerResources = async (invalidateSession = true) => {
    if (invalidateSession) {
      scanSessionIdRef.current += 1;
    }

    const instance = qrReaderRef.current;
    qrReaderRef.current = null;

    if (instance) {
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
    }

    stopOrphanedVideoTracks(readerElementId);
    isCameraActiveRef.current = false;

    if (isMountedRef.current) {
      setIsCameraActive(false);
      setIsStartingCamera(false);
    }
  };

  // Release camera & scanner resources on page unmount or browser tab hide/unload
  useEffect(() => {
    isMountedRef.current = true;

    const handlePageHide = () => {
      void cleanupScannerResources(true);
    };

    window.addEventListener('pagehide', handlePageHide);
    return () => {
      isMountedRef.current = false;
      window.removeEventListener('pagehide', handlePageHide);
      scanSessionIdRef.current += 1;
      const instance = qrReaderRef.current;
      qrReaderRef.current = null;
      isCameraActiveRef.current = false;
      stopOrphanedVideoTracks(readerElementId);
      if (instance) {
        const stopPromise = instance.isScanning
          ? instance.stop().catch(() => {})
          : Promise.resolve();
        stopPromise.finally(() => {
          try {
            instance.clear();
          } catch {
            // Ignore unmount cleanup errors
          }
          stopOrphanedVideoTracks(readerElementId);
        });
      }
    };
  }, []);

  const refreshEnumeratedCameras = async (preferredId?: string) => {
    try {
      if (!navigator.mediaDevices?.enumerateDevices) return;
      const devices = await navigator.mediaDevices.enumerateDevices();
      const videoInputs: CameraDeviceInfo[] = devices
        .filter((d) => d.kind === 'videoinput' && Boolean(d.deviceId))
        .map((d, idx) => ({
          id: d.deviceId,
          label: d.label || `Camera ${idx + 1}`,
        }));
      if (isMountedRef.current && videoInputs.length > 0) {
        setAvailableCameras(videoInputs);
        if (!selectedCameraId && !preferredId) {
          const picked = pickPreferredCamera(videoInputs);
          if (picked) setSelectedCameraId(picked.id);
        } else if (preferredId) {
          setSelectedCameraId(preferredId);
        }
      }
    } catch {
      // Enumeration optional after active stream
    }
  };

  const handleModeChange = async (nextMode: 'camera' | 'upload' | 'manual') => {
    setCameraError(null);
    if (nextMode !== activeMode) {
      await cleanupScannerResources(true);
      setActiveMode(nextMode);
    }
  };

  const startCameraWithFallback = async (
    html5QrCode: Html5Qrcode,
    sessionId: number,
    explicitCameraId?: string
  ) => {
    const scanConfig = {
      fps: 10,
      qrbox: computeResponsiveQrBox,
      disableFlip: false,
    };

    const onScanSuccess = (decodedText: string, decodedResult: any) => {
      if (isHandlingDecodeRef.current || scanSessionIdRef.current !== sessionId || !isMountedRef.current) {
        return;
      }
      isHandlingDecodeRef.current = true;
      const formatName = decodedResult?.result?.format?.formatName || 'Camera Scan';
      void cleanupScannerResources(true).finally(() => {
        if (isMountedRef.current) {
          void handleAnalyzeCode(decodedText, formatName);
        }
      });
    };

    const onScanFrameError = () => {
      // Quiet per-frame scan miss callback
    };

    // Build ordered candidate targets:
    // 1. Explicit camera selection (if user picked one)
    // 2. Soft rear-facing preference for mobile devices (most laptop webcams also accept soft facingMode)
    // 3. Explicit enumerated deviceId fallback (fixes OverconstrainedError / NotFoundError on desktop/laptop webcams)
    // 4. Front-facing user camera fallback
    const candidates: Array<string | MediaTrackConstraints> = [];
    if (explicitCameraId) {
      candidates.push(explicitCameraId);
    } else {
      candidates.push({ facingMode: 'environment' });
    }

    let lastError: unknown = null;
    for (let i = 0; i < candidates.length; i++) {
      if (scanSessionIdRef.current !== sessionId || !isMountedRef.current) {
        return;
      }
      try {
        await html5QrCode.start(candidates[i], scanConfig, onScanSuccess, onScanFrameError);
        return;
      } catch (err) {
        lastError = err;
        const classified = classifyCameraError(err);
        if (!classified.retryableWithFallback) {
          throw err;
        }
      }
    }

    // Fallback: enumerate available video input devices (laptop webcams / USB cameras / mobile cameras)
    if (scanSessionIdRef.current !== sessionId || !isMountedRef.current) {
      return;
    }

    try {
      const devices = await Html5Qrcode.getCameras();
      if (devices && devices.length > 0) {
        const mapped = devices.map((d, idx) => ({
          id: d.id,
          label: d.label || `Camera ${idx + 1}`,
        }));
        if (isMountedRef.current) {
          setAvailableCameras(mapped);
        }
        const preferred = pickPreferredCamera(mapped, explicitCameraId);
        const orderedIds = preferred
          ? [preferred.id, ...mapped.filter((c) => c.id !== preferred.id).map((c) => c.id)]
          : mapped.map((c) => c.id);

        for (const camId of orderedIds) {
          if (scanSessionIdRef.current !== sessionId || !isMountedRef.current) {
            return;
          }
          try {
            await html5QrCode.start(camId, scanConfig, onScanSuccess, onScanFrameError);
            if (isMountedRef.current) {
              setSelectedCameraId(camId);
            }
            return;
          } catch (camErr) {
            lastError = camErr;
          }
        }
      }
    } catch (enumErr) {
      lastError = enumErr;
    }

    // Final generic user-facing fallback for front-only laptops
    if (!explicitCameraId && scanSessionIdRef.current === sessionId && isMountedRef.current) {
      try {
        await html5QrCode.start({ facingMode: 'user' }, scanConfig, onScanSuccess, onScanFrameError);
        return;
      } catch (userErr) {
        lastError = userErr;
      }
    }

    throw lastError || new Error('Unable to initialize camera stream');
  };

  const handleStartCamera = async (overrideCameraId?: string) => {
    setCameraError(null);
    isHandlingDecodeRef.current = false;

    const envCheck = await checkCameraEnvironment();
    if (!envCheck.supported) {
      setCameraError(
        envCheck.errorMessage ||
          'Camera access is unavailable in this browser environment. Please use Image Upload or Manual Entry.'
      );
      return;
    }

    await cleanupScannerResources(true);
    const sessionId = ++scanSessionIdRef.current;

    setIsStartingCamera(true);
    setIsLoading(true);

    try {
      // Wait for React to reveal #vbb-qr-reader-container so html5-qrcode reads non-zero clientWidth
      await waitForNextFrame();
      await waitForNextFrame();

      if (scanSessionIdRef.current !== sessionId || !isMountedRef.current) {
        return;
      }

      const containerEl = document.getElementById(readerElementId);
      if (!containerEl || containerEl.clientWidth === 0) {
        throw new Error('Scanner viewfinder container is not visible yet.');
      }

      const html5QrCode = new Html5Qrcode(readerElementId, {
        verbose: false,
        formatsToSupport: SUPPORTED_SCAN_FORMATS,
        useBarCodeDetectorIfSupported: true,
      });
      qrReaderRef.current = html5QrCode;

      const targetCam = overrideCameraId !== undefined ? overrideCameraId : selectedCameraId || undefined;
      await startCameraWithFallback(html5QrCode, sessionId, targetCam);

      // If user switched tabs, stopped camera, or navigated away while permission prompt resolved, release immediately
      if (scanSessionIdRef.current !== sessionId || !isMountedRef.current) {
        await cleanupScannerResources(false);
        return;
      }

      isCameraActiveRef.current = true;
      setIsCameraActive(true);
      setIsStartingCamera(false);
      void refreshEnumeratedCameras(targetCam);
    } catch (err: any) {
      console.warn('Camera start error:', err);
      await cleanupScannerResources(false);
      if (isMountedRef.current) {
        const classified = classifyCameraError(err, {
          isIframe: envCheck.isIframe,
          isSecureContext: envCheck.isSecureContext,
        });
        setCameraError(classified.message);
      }
    } finally {
      if (isMountedRef.current) {
        setIsStartingCamera(false);
        setIsLoading(false);
      }
    }
  };

  const handleStopCamera = async () => {
    setCameraError(null);
    await cleanupScannerResources(true);
  };

  const handleCameraSelectionChange = async (nextId: string) => {
    setSelectedCameraId(nextId);
    if (isCameraActiveRef.current || isCameraActive) {
      await handleStartCamera(nextId);
    }
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
      await cleanupScannerResources(true);
      fileScanner = new Html5Qrcode(readerElementId, {
        verbose: false,
        formatsToSupport: SUPPORTED_SCAN_FORMATS,
        useBarCodeDetectorIfSupported: true,
      });
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
      if (isMountedRef.current) {
        setIsLoading(false);
      }
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
      if (isMountedRef.current) {
        setCurrentResult(result);
      }
      await HistoryService.saveRecord(result);
    } catch (err: any) {
      if (isMountedRef.current) {
        setCameraError(err.message || 'Code evaluation failed.');
      }
    } finally {
      if (isMountedRef.current) {
        setIsLoading(false);
      }
    }
  };

  const showReaderContainer = activeMode === 'camera' && (isCameraActive || isStartingCamera);

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
          type="button"
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
          type="button"
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
          type="button"
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
        {/* Mode A: Camera Scanner Controls */}
        {activeMode === 'camera' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-white">Live Camera Inspection</h3>
                <p className="text-xs text-slate-400">Position the product barcode or QR code inside the viewfinder frame.</p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {availableCameras.length > 1 && (
                  <div className="flex items-center gap-1.5">
                    <RefreshCw className="w-3.5 h-3.5 text-slate-400" />
                    <select
                      aria-label="Select camera"
                      value={selectedCameraId}
                      onChange={(e) => void handleCameraSelectionChange(e.target.value)}
                      disabled={isStartingCamera}
                      className="px-2.5 py-2 text-xs bg-slate-950 border border-slate-700 rounded-xl text-slate-200 focus:outline-none focus:ring-2 focus:ring-teal-400 max-w-[200px]"
                    >
                      {availableCameras.map((cam, idx) => (
                        <option key={cam.id} value={cam.id}>
                          {cam.label || `Camera ${idx + 1}`}
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                {!isCameraActive && !isStartingCamera ? (
                  <button
                    type="button"
                    onClick={() => void handleStartCamera()}
                    disabled={isLoading}
                    className="px-5 py-2.5 text-xs font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-xl transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    <Camera className="w-4 h-4" />
                    <span>Start Camera</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => void handleStopCamera()}
                    className="px-5 py-2.5 text-xs font-semibold text-rose-300 bg-rose-950/80 hover:bg-rose-900 border border-rose-800 rounded-xl transition-colors flex items-center justify-center gap-2"
                  >
                    <StopCircle className="w-4 h-4" />
                    <span>Stop Camera</span>
                  </button>
                )}
              </div>
            </div>

            {!showReaderContainer && (
              <div className="p-8 border border-dashed border-slate-800 rounded-xl text-center space-y-3 bg-slate-950/40">
                <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
                  <Camera className="w-6 h-6" />
                </div>
                <div className="text-xs text-slate-300 max-w-sm mx-auto">
                  Camera is currently off. Click &ldquo;Start Camera&rdquo; to scan QR codes and retail barcodes using your webcam or mobile rear camera.
                </div>
              </div>
            )}
          </div>
        )}

        {/* Persistent html5-qrcode mount: visible with non-zero dimensions BEFORE html5QrCode.start() runs, and kept in DOM for image upload */}
        <div
          id={readerElementId}
          className={`w-full max-w-md mx-auto rounded-xl overflow-hidden bg-slate-950 border border-slate-800 ${
            showReaderContainer ? 'min-h-[300px]' : 'hidden'
          }`}
        />

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
