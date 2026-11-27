/**
 * Camera Scanner Helper Utilities
 * Handles secure context detection, iframe permissions-policy checks,
 * laptop webcam vs mobile rear-camera selection, responsive QR/1D barcode
 * scan box sizing, and human-friendly camera error classification.
 */

export interface CameraDeviceInfo {
  id: string;
  label?: string;
}

export interface CameraEnvironmentCheck {
  supported: boolean;
  isIframe: boolean;
  isSecureContext: boolean;
  policyBlocked: boolean;
  permissionState?: 'granted' | 'denied' | 'prompt';
  errorMessage?: string;
}

export type CameraErrorCode =
  | 'insecure_context'
  | 'unsupported_browser'
  | 'iframe_blocked'
  | 'permission_denied'
  | 'not_found'
  | 'in_use'
  | 'overconstrained'
  | 'unknown';

export interface ClassifiedCameraError {
  code: CameraErrorCode;
  retryableWithFallback: boolean;
  message: string;
}

export interface CameraEnvProbeInput {
  isSecureContext?: boolean;
  protocol?: string;
  hostname?: string;
  hasMediaDevices?: boolean;
  hasGetUserMedia?: boolean;
  isIframe?: boolean;
  policyAllowsCamera?: boolean | null;
  permissionState?: 'granted' | 'denied' | 'prompt';
}

/**
 * Check whether browser secure context, mediaDevices API, iframe policy,
 * and Permissions API allow camera initialization.
 */
export async function checkCameraEnvironment(
  override?: CameraEnvProbeInput
): Promise<CameraEnvironmentCheck> {
  if (override) {
    return evaluateCameraEnvironment(override);
  }

  if (typeof window === 'undefined' || typeof navigator === 'undefined') {
    return {
      supported: false,
      isIframe: false,
      isSecureContext: false,
      policyBlocked: false,
      errorMessage: 'Camera scanning is only available inside an interactive browser session.',
    };
  }

  const host = (window.location?.hostname || '').toLowerCase();
  const isLocalHost = host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
  const isSecureContext = Boolean(window.isSecureContext || window.location?.protocol === 'https:' || isLocalHost);

  let isIframe = false;
  try {
    isIframe = window.self !== window.top;
  } catch {
    isIframe = true;
  }

  let policyAllowsCamera: boolean | null = null;
  try {
    const docAny = document as any;
    const policy = docAny?.permissionsPolicy || docAny?.featurePolicy;
    if (policy && typeof policy.allowsFeature === 'function') {
      policyAllowsCamera = Boolean(policy.allowsFeature('camera'));
    }
  } catch {
    policyAllowsCamera = null;
  }

  let permissionState: 'granted' | 'denied' | 'prompt' | undefined;
  try {
    if (navigator.permissions && typeof navigator.permissions.query === 'function') {
      const status = await navigator.permissions.query({ name: 'camera' as PermissionName });
      if (status?.state === 'granted' || status?.state === 'denied' || status?.state === 'prompt') {
        permissionState = status.state;
      }
    }
  } catch {
    // Safari / some browsers do not support querying 'camera' via Permissions API
  }

  return evaluateCameraEnvironment({
    isSecureContext,
    protocol: window.location?.protocol,
    hostname: host,
    hasMediaDevices: Boolean(navigator.mediaDevices),
    hasGetUserMedia: typeof navigator.mediaDevices?.getUserMedia === 'function',
    isIframe,
    policyAllowsCamera,
    permissionState,
  });
}

/**
 * Pure evaluator for camera environment preconditions (easy to unit test in Node).
 */
export function evaluateCameraEnvironment(probe: CameraEnvProbeInput): CameraEnvironmentCheck {
  const isIframe = Boolean(probe.isIframe);
  const host = (probe.hostname || '').toLowerCase();
  const isLocalHost = host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
  const isSecureContext = Boolean(
    probe.isSecureContext || probe.protocol === 'https:' || isLocalHost
  );

  if (!isSecureContext) {
    return {
      supported: false,
      isIframe,
      isSecureContext: false,
      policyBlocked: false,
      permissionState: probe.permissionState,
      errorMessage:
        'Camera access requires a secure HTTPS connection (or localhost). Open this app over HTTPS or use Image Upload / Manual Entry.',
    };
  }

  if (probe.policyAllowsCamera === false) {
    return {
      supported: false,
      isIframe,
      isSecureContext: true,
      policyBlocked: true,
      permissionState: probe.permissionState,
      errorMessage: isIframe
        ? 'Camera access is blocked by this embedded iframe permissions policy (missing allow="camera"). Open the app in a new tab or use Image Upload / Manual Entry.'
        : 'Camera access is blocked by the page Permissions-Policy header. Enable camera permission in site settings or use Image Upload / Manual Entry.',
    };
  }

  if (!probe.hasMediaDevices || !probe.hasGetUserMedia) {
    return {
      supported: false,
      isIframe,
      isSecureContext: true,
      policyBlocked: false,
      permissionState: probe.permissionState,
      errorMessage: isIframe
        ? 'Live camera streaming is unavailable inside this embedded frame or browser. Try opening the app in a separate browser tab, or use Image Upload / Manual Entry.'
        : 'Your browser does not support live camera access (MediaDevices.getUserMedia unavailable). Please use Image Upload or Manual Entry.',
    };
  }

  if (probe.permissionState === 'denied') {
    return {
      supported: false,
      isIframe,
      isSecureContext: true,
      policyBlocked: false,
      permissionState: 'denied',
      errorMessage: isIframe
        ? 'Camera permission is denied in your browser or blocked for this embedded frame. Allow camera access in browser site settings (or open in a dedicated tab) and try again.'
        : 'Camera permission was denied in your browser. Click the camera/lock icon in your address bar to allow camera access, then click Start Camera.',
    };
  }

  return {
    supported: true,
    isIframe,
    isSecureContext: true,
    policyBlocked: false,
    permissionState: probe.permissionState,
  };
}

/**
 * Pick best available camera:
 * - Honor explicit preferredId when present
 * - Otherwise prefer rear/back/environment cameras for mobile packaging scans
 * - Fall back cleanly to first available camera (laptop webcam / external USB cam)
 */
export function pickPreferredCamera(
  cameras: CameraDeviceInfo[],
  preferredId?: string
): CameraDeviceInfo | undefined {
  if (!cameras || cameras.length === 0) return undefined;

  if (preferredId) {
    const matched = cameras.find((c) => c.id === preferredId);
    if (matched) return matched;
  }

  const rearCamera = cameras.find((cam) => {
    const lbl = (cam.label || '').toLowerCase();
    return (
      (lbl.includes('back') ||
        lbl.includes('rear') ||
        lbl.includes('environment') ||
        lbl.includes('world')) &&
      !lbl.includes('front') &&
      !lbl.includes('user')
    );
  });

  return rearCamera || cameras[0];
}

/**
 * Compute responsive viewfinder scan box dimensions supporting both
 * square 2D QR codes and wide 1D retail barcodes (UPC-A, EAN-13, Code-128).
 */
export function computeResponsiveQrBox(
  viewfinderWidth: number,
  viewfinderHeight: number
): { width: number; height: number } {
  const safeW = Math.max(120, Math.floor(viewfinderWidth || 300));
  const safeH = Math.max(100, Math.floor(viewfinderHeight || 240));

  const targetW = Math.min(safeW - 16, Math.max(180, Math.floor(safeW * 0.82)));
  const targetH = Math.min(safeH - 16, Math.max(110, Math.floor(safeH * 0.58)));

  return {
    width: Math.max(60, Math.min(safeW, targetW)),
    height: Math.max(60, Math.min(safeH, targetH)),
  };
}

/**
 * Translate raw MediaDevices / html5-qrcode errors into clear user-facing guidance
 * and indicate whether retrying with an alternate camera constraint should be attempted.
 */
export function classifyCameraError(
  err: unknown,
  context: { isIframe?: boolean; isSecureContext?: boolean } = {}
): ClassifiedCameraError {
  const errName = (err as any)?.name ? String((err as any).name) : '';
  const rawMessage = err instanceof Error ? err.message : String(err || '');
  const combined = `${errName} ${rawMessage}`.toLowerCase();

  if (context.isSecureContext === false || combined.includes('secure context') || combined.includes('only supported in secure')) {
    return {
      code: 'insecure_context',
      retryableWithFallback: false,
      message:
        'Camera access requires a secure HTTPS connection (or localhost). Open the app over HTTPS or use Image Upload / Manual Entry.',
    };
  }

  if (
    combined.includes('permissions policy') ||
    combined.includes('feature policy') ||
    combined.includes('disallowed by permissions')
  ) {
    return {
      code: 'iframe_blocked',
      retryableWithFallback: false,
      message: context.isIframe
        ? 'Camera access is blocked by the embedded iframe permissions policy. Open the app directly in a new browser tab or use Image Upload / Manual Entry.'
        : 'Camera access is blocked by browser Permissions-Policy rules. Enable camera access in browser settings or use Image Upload / Manual Entry.',
    };
  }

  if (
    combined.includes('notallowederror') ||
    combined.includes('permissiondeniederror') ||
    combined.includes('permission denied') ||
    combined.includes('permission dismissed')
  ) {
    return {
      code: 'permission_denied',
      retryableWithFallback: false,
      message: context.isIframe
        ? 'Camera permission was denied or blocked inside this embedded frame. Allow camera permission in browser settings (or open in a dedicated tab), then try again.'
        : 'Camera permission was denied. Allow camera access in your browser site settings and click Start Camera again, or use Image Upload / Manual Entry.',
    };
  }

  if (
    combined.includes('notfounderror') ||
    combined.includes('devicesnotfounderror') ||
    combined.includes('requested device not found')
  ) {
    return {
      code: 'not_found',
      retryableWithFallback: true,
      message:
        'No camera device was found on this device. Connect a webcam or use Image Upload / Manual Entry.',
    };
  }

  if (
    combined.includes('overconstrainederror') ||
    combined.includes('constraintnotfounderror') ||
    combined.includes('overconstrained')
  ) {
    return {
      code: 'overconstrained',
      retryableWithFallback: true,
      message:
        'Selected camera constraints are not supported by this webcam. Trying fallback camera or use Image Upload / Manual Entry.',
    };
  }

  if (
    combined.includes('notreadableerror') ||
    combined.includes('trackstarterror') ||
    combined.includes('could not start video source') ||
    combined.includes('device in use')
  ) {
    return {
      code: 'in_use',
      retryableWithFallback: true,
      message:
        'Camera is currently unavailable or in use by another application or browser tab. Close other video apps and retry, or use Image Upload / Manual Entry.',
    };
  }

  if (combined.includes('not supported') || combined.includes('mediadevices')) {
    return {
      code: 'unsupported_browser',
      retryableWithFallback: false,
      message:
        'Live camera streaming is not supported in this browser or context. Please use Image Upload or Manual Entry.',
    };
  }

  return {
    code: 'unknown',
    retryableWithFallback: true,
    message:
      'Unable to start the camera. Verify browser camera permissions, ensure no other app is locking the webcam, or use Image Upload / Manual Entry.',
  };
}
