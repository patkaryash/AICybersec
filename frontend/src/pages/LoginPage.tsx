import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  Shield,
  Lock,
  Mail,
  AlertTriangle,
  ArrowRight,
  Eye,
  EyeOff,
  Radio,
} from 'lucide-react';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, error, clearError } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [clientError, setClientError] = useState<string | null>(null);

  const from = (location.state as { from?: { pathname?: string } })?.from?.pathname || '/';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    setClientError(null);

    const trimmedEmail = email.trim();
    if (!trimmedEmail || !password) {
      setClientError('Email and password are required.');
      return;
    }

    try {
      setIsSubmitting(true);
      await login({ email: trimmedEmail, password });
      navigate(from, { replace: true });
    } catch {
      // Backend error is stored in AuthContext
      setIsSubmitting(false);
    }
  };

  const handleDemoBypass = () => {
    localStorage.setItem('sentinel_demo_mode', 'true');
    navigate('/', { replace: true });
  };

  const displayError = clientError || error;

  return (
    <div className="min-h-screen bg-sentinel-bg text-sentinel-text flex items-center justify-center p-4">
      {/* Background Ambience */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[400px] bg-cyan-900/10 rounded-full blur-[120px]" />
        <div className="absolute bottom-1/4 right-1/4 w-[400px] h-[300px] bg-purple-900/10 rounded-full blur-[100px]" />
      </div>

      <div className="relative w-full max-w-md">
        {/* Brand Card Header */}
        <div className="text-center mb-6 space-y-2">
          <div className="inline-flex w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-600/20 border border-cyan-500/40 items-center justify-center text-sentinel-cyan shadow-lg shadow-cyan-950/50 mb-1">
            <Shield size={26} className="stroke-[2.2]" />
          </div>
          <div className="flex items-center justify-center gap-1.5">
            <h1 className="text-2xl font-bold tracking-tight text-sentinel-text">
              CyberSec <span className="text-sentinel-cyan">AI</span>
            </h1>
            <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold bg-cyan-950/80 text-sentinel-cyan border border-cyan-800/60">
              v1.0
            </span>
          </div>
          <p className="text-xs text-sentinel-muted">
            Autonomous Penetration Testing & Threat Telemetry Platform
          </p>
        </div>

        {/* Login Form Card */}
        <div className="bg-sentinel-surface/90 border border-sentinel-border rounded-2xl p-6 sm:p-8 backdrop-blur-xl shadow-2xl space-y-6">
          <div className="space-y-1">
            <h2 className="text-base font-semibold text-sentinel-text">Operator Authentication</h2>
            <p className="text-xs text-sentinel-dim">
              Sign in with your verified credentials to access authorized lab scopes.
            </p>
          </div>

          {displayError && (
            <div className="p-3 rounded-lg border border-rose-900/60 bg-rose-950/40 text-xs text-rose-300 flex items-start gap-2.5">
              <AlertTriangle size={15} className="shrink-0 mt-0.5 text-rose-400" />
              <div className="flex-1 leading-relaxed">{displayError}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="login-email"
                className="block text-xs font-mono font-medium text-sentinel-muted mb-1.5 uppercase tracking-wider"
              >
                Email Address
              </label>
              <div className="relative">
                <input
                  id="login-email"
                  type="email"
                  autoComplete="email"
                  disabled={isSubmitting}
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="operator@aicybersec.dev"
                  className="w-full pl-9 pr-4 py-2.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs sm:text-sm text-sentinel-text font-mono placeholder:text-sentinel-dim focus:outline-none focus:border-sentinel-cyan transition-colors"
                />
                <div className="absolute left-3 top-3 text-sentinel-dim">
                  <Mail size={15} />
                </div>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label
                  htmlFor="login-password"
                  className="block text-xs font-mono font-medium text-sentinel-muted uppercase tracking-wider"
                >
                  Password
                </label>
              </div>
              <div className="relative">
                <input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  disabled={isSubmitting}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-10 py-2.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs sm:text-sm text-sentinel-text font-mono placeholder:text-sentinel-dim focus:outline-none focus:border-sentinel-cyan transition-colors"
                />
                <div className="absolute left-3 top-3 text-sentinel-dim">
                  <Lock size={15} />
                </div>
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute right-3 top-3 text-sentinel-dim hover:text-sentinel-text"
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full mt-2 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-sentinel-cyan text-sentinel-bg font-semibold text-xs tracking-wider uppercase hover:bg-sentinel-cyan-hover transition-colors shadow-md disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {isSubmitting ? (
                <>
                  <div className="w-4 h-4 border-2 border-sentinel-bg border-t-transparent rounded-full animate-spin" />
                  <span>Verifying Token...</span>
                </>
              ) : (
                <>
                  <span>Authenticate Session</span>
                  <ArrowRight size={14} />
                </>
              )}
            </button>
          </form>

          <div className="pt-2 border-t border-sentinel-border/60 flex flex-col gap-3 text-center text-xs">
            <div className="text-sentinel-muted">
              Don&apos;t have an authorized account?{' '}
              <Link
                to="/register"
                className="text-sentinel-cyan hover:underline font-medium font-mono"
              >
                Register Laboratory Access
              </Link>
            </div>

            <button
              type="button"
              onClick={handleDemoBypass}
              className="text-[11px] font-mono text-sentinel-dim hover:text-sentinel-text flex items-center justify-center gap-1.5 transition-colors py-1 rounded hover:bg-sentinel-elevated/40"
            >
              <Radio size={12} className="text-cyan-400" />
              <span>Explore Simulated Demo Mode (Offline)</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
