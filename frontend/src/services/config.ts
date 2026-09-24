/**
 * Sentinel AI — Configuration and Mode Detection
 */

export function isDemoMode(): boolean {
  // If explicitly configured in environment
  if (import.meta.env.VITE_DEMO_MODE === 'true') {
    return true;
  }

  // If set by user in localStorage
  return localStorage.getItem('sentinel_demo_mode') === 'true';
}

export function setDemoMode(enabled: boolean): void {
  if (enabled) {
    localStorage.setItem('sentinel_demo_mode', 'true');
  } else {
    localStorage.removeItem('sentinel_demo_mode');
  }
}
