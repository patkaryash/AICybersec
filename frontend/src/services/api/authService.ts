/**
 * Authentication Service for CyberSec AI backend (/api/v1/auth)
 */

import { apiClient } from '../apiClient';
import {
  LoginRequest,
  RegisterRequest,
  TokenResponse,
  UserOut,
} from '../../types/contract';

export const authService = {
  /**
   * Authenticate with email & password.
   * Backend returns 200 with { access_token, token_type: "bearer", expires_in }.
   */
  async login(credentials: LoginRequest): Promise<TokenResponse> {
    return apiClient.post<TokenResponse>('/auth/login', credentials);
  },

  /**
   * Register a new user account.
   * Backend returns 201 with UserOut.
   */
  async register(data: RegisterRequest): Promise<UserOut> {
    return apiClient.post<UserOut>('/auth/register', data);
  },

  /**
   * Fetch current authenticated user.
   * Backend returns 200 with UserOut.
   */
  async getCurrentUser(): Promise<UserOut> {
    return apiClient.get<UserOut>('/auth/me');
  },
};
