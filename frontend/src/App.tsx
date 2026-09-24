import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ScanProvider } from './context/ScanContext';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { AppLayout } from './layouts/AppLayout';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { DashboardPage } from './pages/DashboardPage';
import { NewPentestPage } from './pages/NewPentestPage';
import { LiveAgentPage } from './pages/LiveAgentPage';
import { FindingsPage } from './pages/FindingsPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <ScanProvider>
        <BrowserRouter>
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
        </BrowserRouter>
      </ScanProvider>
    </AuthProvider>
  );
};

export default App;
