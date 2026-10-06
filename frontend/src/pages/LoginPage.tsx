import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
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
    <div className="min-h-screen bg-[#09090B] flex items-center justify-center px-4 text-zinc-100">

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: 'easeOut' }}
        className="relative w-full max-w-md"
      >
        {/* Brand Card Header */}
        <div className="text-center mb-6 space-y-2">
          <div className="inline-flex w-12 h-12 rounded-xl bg-zinc-100 items-center justify-center text-zinc-900 shadow-md mb-1">
            <Shield size={26} className="stroke-[2.2]" />
          </div>
          <div className="flex items-center justify-center gap-1.5">
            <h1 className="text-2xl font-semibold tracking-tight text-white">
              Sentinel <span className="text-zinc-400">AI</span>
            </h1>
            <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold bg-zinc-800 text-zinc-300 border border-zinc-700">
              v1.0
            </span>
          </div>
          <p className="text-sm text-zinc-400">
            Autonomous Penetration Testing & Threat Intelligence Platform
          </p>
        </div>

        {/* Login Form Card */}
        <div className="w-full max-w-md rounded-2xl border border-zinc-800 bg-[#121214] p-8 shadow-2xl space-y-6">
          <div className="space-y-1">
            <h2 className="text-xl font-semibold tracking-tight text-white">Operator Authentication</h2>
            <p className="text-sm text-zinc-400 mt-1">
              Sign in with your verified credentials to access authorized lab scopes.
            </p>
          </div>

          {displayError && (
            <div className="p-3.5 rounded-xl border border-red-900/50 bg-red-950/50 text-xs text-red-400 flex items-start gap-2.5 shadow-2xs">
              <AlertTriangle size={15} className="shrink-0 mt-0.5 text-red-500" />
              <div className="flex-1 leading-relaxed">{displayError}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="login-email"
                className="block text-xs font-mono font-bold text-zinc-400 mb-1.5 uppercase tracking-wider"
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
                  placeholder="operator@sentinelai.dev"
                  className="w-full pl-9 pr-4 py-2.5 rounded-lg border border-zinc-800 bg-[#18181B] text-sm text-zinc-100 placeholder-zinc-500 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600 transition-all"
                />
                <div className="absolute left-3 top-3 text-zinc-500">
                  <Mail size={15} />
                </div>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label
                  htmlFor="login-password"
                  className="block text-xs font-mono font-bold text-zinc-400 uppercase tracking-wider"
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
                  className="w-full pl-9 pr-10 py-2.5 rounded-lg border border-zinc-800 bg-[#18181B] text-sm text-zinc-100 placeholder-zinc-500 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600 transition-all"
                />
                <div className="absolute left-3 top-3 text-zinc-500">
                  <Lock size={15} />
                </div>
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute right-3 top-3 text-zinc-500 hover:text-zinc-300"
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full mt-2 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-zinc-100 text-zinc-900 font-medium text-sm transition hover:bg-zinc-200 focus:outline-none disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {isSubmitting ? (
                <>
                  <div className="w-4 h-4 border-2 border-zinc-900 border-t-transparent rounded-full animate-spin" />
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

          <div className="pt-2 border-t border-zinc-800 flex flex-col gap-3 text-center text-xs">
            <div className="text-zinc-400">
              Don&apos;t have an authorized account?{' '}
              <Link
                to="/register"
                className="text-sm font-medium text-white hover:underline"
              >
                Register Laboratory Access
              </Link>
            </div>

            <button
              type="button"
              onClick={handleDemoBypass}
              className="w-full rounded-lg border border-zinc-800 bg-[#18181B] py-2.5 text-sm font-medium text-zinc-100 transition hover:bg-zinc-800 focus:outline-none flex items-center justify-center gap-1.5"
            >
              <Radio size={12} className="text-zinc-400" />
              <span>Explore Simulated Demo Mode (Offline)</span>
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
};
