import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
} from 'react';
import { UserOut, LoginRequest, RegisterRequest } from '../types/contract';
import { authService } from '../services/api/authService';
import { apiClient, ApiClientError } from '../services/apiClient';

const AUTH_TOKEN_KEY = 'sentinel_auth_token';

interface AuthContextType {
  user: UserOut | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (credentials: LoginRequest) => Promise<void>;
  register: (data: RegisterRequest) => Promise<void>;
  logout: () => void;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [user, setUser] = useState<UserOut | null>(null);
  const [token, setTokenState] = useState<string | null>(() => {
    return localStorage.getItem(AUTH_TOKEN_KEY);
  });
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const isRestoringRef = useRef(false);

  const logout = useCallback(() => {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    apiClient.setToken(null);
    setTokenState(null);
    setUser(null);
    setError(null);
  }, []);

  // Listen for centralized 401 Unauthorized notifications from apiClient
  useEffect(() => {
    const unsubscribe = apiClient.onUnauthorized(() => {
      logout();
    });
    return unsubscribe;
  }, [logout]);

  // Session restoration on startup
  useEffect(() => {
    const restoreSession = async () => {
      const storedToken = localStorage.getItem(AUTH_TOKEN_KEY);
      if (!storedToken) {
        setIsLoading(false);
        return;
      }

      if (isRestoringRef.current) return;
      isRestoringRef.current = true;

      try {
        apiClient.setToken(storedToken);
        const currentUser = await authService.getCurrentUser();
        setUser(currentUser);
        setTokenState(storedToken);
      } catch (err) {
        console.warn('Session restoration failed:', err);
        logout();
      } finally {
        setIsLoading(false);
        isRestoringRef.current = false;
      }
    };

    restoreSession();
  }, [logout]);

  const login = async (credentials: LoginRequest): Promise<void> => {
    setError(null);
    try {
      const tokenRes = await authService.login(credentials);
      localStorage.setItem(AUTH_TOKEN_KEY, tokenRes.access_token);
      localStorage.removeItem('sentinel_demo_mode');
      apiClient.setToken(tokenRes.access_token);
      setTokenState(tokenRes.access_token);

      // Immediately fetch current user profile
      const currentUser = await authService.getCurrentUser();
      setUser(currentUser);
    } catch (err: unknown) {
      const message =
        err instanceof ApiClientError
          ? err.message
          : 'Authentication failed. Please verify your credentials.';
      setError(message);
      throw err;
    }
  };

  const register = async (data: RegisterRequest): Promise<void> => {
    setError(null);
    try {
      await authService.register(data);
      // Auto-login after successful registration
      await login({ email: data.email, password: data.password });
    } catch (err: unknown) {
      const message =
        err instanceof ApiClientError
          ? err.message
          : 'Registration failed. Please check your input and try again.';
      setError(message);
      throw err;
    }
  };

  const clearError = () => setError(null);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: Boolean(user && token),
        isLoading,
        error,
        login,
        register,
        logout,
        clearError,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
