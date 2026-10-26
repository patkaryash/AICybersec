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
    <div className="min-h-screen bg-[#F4F7FB] text-[#0B1220] flex items-center justify-center p-4">
      {/* Background Ambience */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[400px] bg-blue-400/5 rounded-full blur-[120px]" />
        <div className="absolute bottom-1/4 right-1/4 w-[400px] h-[300px] bg-indigo-400/5 rounded-full blur-[100px]" />
      </div>

      <div className="relative w-full max-w-md">
        {/* Brand Card Header */}
        <div className="text-center mb-6 space-y-2">
          <div className="inline-flex w-12 h-12 rounded-xl bg-[#1D4ED8] items-center justify-center text-white shadow-md shadow-[#1D4ED8]/25 mb-1">
            <Shield size={26} className="stroke-[2.2]" />
          </div>
          <div className="flex items-center justify-center gap-1.5">
            <h1 className="text-2xl font-bold tracking-tight text-[#0B1220]">
              Sentinel <span className="text-[#1D4ED8]">AI</span>
            </h1>
            <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold bg-blue-50 text-[#1D4ED8] border border-blue-200">
              Registration
            </span>
          </div>
          <p className="text-xs text-[#475569]">
            Autonomous Security Operations &amp; Lab Access Registration
          </p>
        </div>

        {/* Register Form Card */}
        <div className="bg-white/90 backdrop-blur-md border border-slate-200/80 rounded-2xl p-6 sm:p-8 shadow-sm space-y-6">
          <div className="space-y-1">
            <h2 className="text-base font-bold text-[#0B1220]">Create Security Account</h2>
            <p className="text-xs text-[#64748B]">
              New accounts receive operator role for authorized security assessments.
            </p>
          </div>

          {displayError && (
            <div className="p-3.5 rounded-xl border border-rose-200 bg-rose-50 text-xs text-rose-800 flex items-start gap-2.5 shadow-2xs">
              <AlertTriangle size={15} className="shrink-0 mt-0.5 text-rose-600" />
              <div className="flex-1 leading-relaxed">{displayError}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="register-name"
                className="block text-xs font-mono font-bold text-[#475569] mb-1.5 uppercase tracking-wider"
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
                  className="w-full pl-9 pr-4 py-2.5 rounded-lg bg-[#F4F7FB] border border-[#D8E1EB] text-xs sm:text-sm text-[#0B1220] font-mono placeholder:text-[#64748B] focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/25 transition-all"
                />
                <div className="absolute left-3 top-3 text-[#64748B]">
                  <User size={15} />
                </div>
              </div>
            </div>

            <div>
              <label
                htmlFor="register-email"
                className="block text-xs font-mono font-bold text-[#475569] mb-1.5 uppercase tracking-wider"
              >
                Email Address <span className="text-rose-600">*</span>
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
                  className="w-full pl-9 pr-4 py-2.5 rounded-lg bg-[#F4F7FB] border border-[#D8E1EB] text-xs sm:text-sm text-[#0B1220] font-mono placeholder:text-[#64748B] focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/25 transition-all"
                />
                <div className="absolute left-3 top-3 text-[#64748B]">
                  <Mail size={15} />
                </div>
              </div>
            </div>

            <div>
              <label
                htmlFor="register-password"
                className="block text-xs font-mono font-bold text-[#475569] mb-1.5 uppercase tracking-wider"
              >
                Password (min 8 chars) <span className="text-rose-600">*</span>
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
                  className="w-full pl-9 pr-10 py-2.5 rounded-lg bg-[#F4F7FB] border border-[#D8E1EB] text-xs sm:text-sm text-[#0B1220] font-mono placeholder:text-[#64748B] focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/25 transition-all"
                />
                <div className="absolute left-3 top-3 text-[#64748B]">
                  <Lock size={15} />
                </div>
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute right-3 top-3 text-[#64748B] hover:text-[#0B1220]"
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <div>
              <label
                htmlFor="register-confirm-password"
                className="block text-xs font-mono font-bold text-[#475569] mb-1.5 uppercase tracking-wider"
              >
                Confirm Password <span className="text-rose-600">*</span>
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
                  className="w-full pl-9 pr-10 py-2.5 rounded-lg bg-[#F4F7FB] border border-[#D8E1EB] text-xs sm:text-sm text-[#0B1220] font-mono placeholder:text-[#64748B] focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/25 transition-all"
                />
                <div className="absolute left-3 top-3 text-[#64748B]">
                  <Lock size={15} />
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full mt-2 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-[#1D4ED8] text-white font-semibold text-xs tracking-wider uppercase hover:bg-[#1E40AF] transition-colors shadow-2xs disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {isSubmitting ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
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

          <div className="pt-2 border-t border-[#D8E1EB] text-center text-xs">
            <span className="text-[#475569]">Already registered? </span>
            <Link
              to="/login"
              className="text-[#1D4ED8] hover:underline font-semibold font-mono"
            >
              Sign In Here
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
