import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ScanProvider } from './context/ScanContext';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { AppLayout } from './layouts/AppLayout';

// Route-level code splitting: loads chunks on-demand instead of 2.5MB upfront
const LoginPage = lazy(() => import('./pages/LoginPage').then((m) => ({ default: m.LoginPage })));
const RegisterPage = lazy(() => import('./pages/RegisterPage').then((m) => ({ default: m.RegisterPage })));
const DashboardPage = lazy(() => import('./pages/DashboardPage').then((m) => ({ default: m.DashboardPage })));
const NewPentestPage = lazy(() => import('./pages/NewPentestPage').then((m) => ({ default: m.NewPentestPage })));
const LiveAgentPage = lazy(() => import('./pages/LiveAgentPage').then((m) => ({ default: m.LiveAgentPage })));
const FindingsPage = lazy(() => import('./pages/FindingsPage').then((m) => ({ default: m.FindingsPage })));
const ScanHistoryPage = lazy(() => import('./pages/ScanHistoryPage').then((m) => ({ default: m.ScanHistoryPage })));

const PageLoadingFallback: React.FC = () => (
  <div className="min-h-[50vh] flex flex-col items-center justify-center p-8 text-center">
    <div className="inline-block animate-spin w-7 h-7 border-2 border-sentinel-cyan border-t-transparent rounded-full mb-3" />
    <span className="text-xs text-sentinel-muted font-mono tracking-wider">LOADING TELEMETRY MODULE...</span>
  </div>
);

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <ScanProvider>
        <BrowserRouter>
          <Suspense fallback={<PageLoadingFallback />}>
            <Routes>
              {/* Public Authentication Routes */}
              <Route path="/login" element={<LoginPage />} />
              <Route path="/register" element={<RegisterPage />} />

              {/* Protected Platform Routes */}
              <Route element={<ProtectedRoute />}>
                <Route element={<AppLayout />}>
                  <Route path="/" element={<DashboardPage />} />
                  <Route path="/new-scan" element={<NewPentestPage />} />
                  <Route path="/agent" element={<LiveAgentPage />} />
                  <Route path="/agent/:scanId" element={<LiveAgentPage />} />
                  <Route path="/findings" element={<FindingsPage />} />
                  <Route path="/history" element={<ScanHistoryPage />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Route>
              </Route>
            </Routes>
          </Suspense>
        </BrowserRouter>
      </ScanProvider>
    </AuthProvider>
  );
};

export default App;
