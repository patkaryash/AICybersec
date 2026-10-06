import React from 'react';
import { Navigate, useLocation, Outlet } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { Shield } from 'lucide-react';

interface ProtectedRouteProps {
  children?: React.ReactNode;
  allowDemo?: boolean;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  allowDemo = false,
}) => {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  const isDemo =
    allowDemo ||
    import.meta.env.VITE_DEMO_MODE === 'true' ||
    localStorage.getItem('sentinel_demo_mode') === 'true';

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#F4F7FB] flex flex-col items-center justify-center p-4">
        <div className="w-12 h-12 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center text-[#1D4ED8] mb-4 animate-pulse shadow-2xs">
          <Shield size={24} />
        </div>
        <div className="inline-block animate-spin w-6 h-6 border-2 border-[#1D4ED8] border-t-transparent rounded-full mb-3" />
        <p className="text-xs text-[#475569] font-mono tracking-wider uppercase">
          Verifying Security Session...
        </p>
      </div>
    );
  }

  if (!isAuthenticated && !isDemo) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children ? <>{children}</> : <Outlet />;
};
