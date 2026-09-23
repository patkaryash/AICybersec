import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ScanProvider } from './context/ScanContext';
import { AppLayout } from './layouts/AppLayout';
import { DashboardPage } from './pages/DashboardPage';
import { NewPentestPage } from './pages/NewPentestPage';
import { LiveAgentPage } from './pages/LiveAgentPage';
import { FindingsPage } from './pages/FindingsPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';

export const App: React.FC = () => {
  return (
    <ScanProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<AppLayout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/new-scan" element={<NewPentestPage />} />
            <Route path="/agent" element={<LiveAgentPage />} />
            <Route path="/agent/:scanId" element={<LiveAgentPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/history" element={<ScanHistoryPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ScanProvider>
  );
};

export default App;
