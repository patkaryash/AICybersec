import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  Shield,
  Lock,
  Mail,
  User,
  AlertTriangle,
  ArrowRight,
  Eye,
  EyeOff,
} from 'lucide-react';

export const RegisterPage: React.FC = () => {
  const navigate = useNavigate();
  const { register, error, clearError } = useAuth();

  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [clientError, setClientError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    setClientError(null);

    const trimmedEmail = email.trim();
    if (!trimmedEmail) {
      setClientError('A valid email address is required.');
      return;
    }

    if (password.length < 8) {
      setClientError('Password must contain at least 8 characters.');
      return;
    }

    if (password !== confirmPassword) {
      setClientError('Passwords do not match.');
      return;
    }

    try {
      setIsSubmitting(true);
      await register({
        email: trimmedEmail,
        password,
        display_name: displayName.trim() || undefined,
      });
      navigate('/', { replace: true });
    } catch {
      setIsSubmitting(false);
    }
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
              Registration
            </span>
          </div>
          <p className="text-xs text-sentinel-muted">
            Request Authorized Laboratory Operator Credentials
          </p>
        </div>

        {/* Register Form Card */}
        <div className="bg-sentinel-surface/90 border border-sentinel-border rounded-2xl p-6 sm:p-8 backdrop-blur-xl shadow-2xl space-y-6">
          <div className="space-y-1">
            <h2 className="text-base font-semibold text-sentinel-text">Create Security Account</h2>
            <p className="text-xs text-sentinel-dim">
              New accounts receive operator role for authorized security assessments.
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
                htmlFor="register-name"
                className="block text-xs font-mono font-medium text-sentinel-muted mb-1.5 uppercase tracking-wider"
              >
                Operator Name (Optional)
              </label>
              <div className="relative">
                <input
                  id="register-name"
                  type="text"
                  autoComplete="name"
                  disabled={isSubmitting}
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Security Specialist"
                  className="w-full pl-9 pr-4 py-2.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs sm:text-sm text-sentinel-text font-mono placeholder:text-sentinel-dim focus:outline-none focus:border-sentinel-cyan transition-colors"
                />
                <div className="absolute left-3 top-3 text-sentinel-dim">
                  <User size={15} />
                </div>
              </div>
            </div>

            <div>
              <label
                htmlFor="register-email"
                className="block text-xs font-mono font-medium text-sentinel-muted mb-1.5 uppercase tracking-wider"
              >
                Email Address <span className="text-rose-400">*</span>
              </label>
              <div className="relative">
                <input
                  id="register-email"
                  type="email"
                  autoComplete="email"
                  required
                  disabled={isSubmitting}
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="specialist@corp.internal"
                  className="w-full pl-9 pr-4 py-2.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs sm:text-sm text-sentinel-text font-mono placeholder:text-sentinel-dim focus:outline-none focus:border-sentinel-cyan transition-colors"
                />
                <div className="absolute left-3 top-3 text-sentinel-dim">
                  <Mail size={15} />
                </div>
              </div>
            </div>

            <div>
              <label
                htmlFor="register-password"
                className="block text-xs font-mono font-medium text-sentinel-muted mb-1.5 uppercase tracking-wider"
              >
                Password (min 8 chars) <span className="text-rose-400">*</span>
              </label>
              <div className="relative">
                <input
                  id="register-password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  required
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

            <div>
              <label
                htmlFor="register-confirm-password"
                className="block text-xs font-mono font-medium text-sentinel-muted mb-1.5 uppercase tracking-wider"
              >
                Confirm Password <span className="text-rose-400">*</span>
              </label>
              <div className="relative">
                <input
                  id="register-confirm-password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  required
                  disabled={isSubmitting}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-10 py-2.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs sm:text-sm text-sentinel-text font-mono placeholder:text-sentinel-dim focus:outline-none focus:border-sentinel-cyan transition-colors"
                />
                <div className="absolute left-3 top-3 text-sentinel-dim">
                  <Lock size={15} />
                </div>
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
                  <span>Registering Profile...</span>
                </>
              ) : (
                <>
                  <span>Create Account</span>
                  <ArrowRight size={14} />
                </>
              )}
            </button>
          </form>

          <div className="pt-2 border-t border-sentinel-border/60 text-center text-xs">
            <span className="text-sentinel-muted">Already registered? </span>
            <Link
              to="/login"
              className="text-sentinel-cyan hover:underline font-medium font-mono"
            >
              Sign In Here
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
