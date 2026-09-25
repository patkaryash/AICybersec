/**
 * Centralized API Client for CyberSec AI backend (/api/v1)
 *
 * Implements:
 * - Base URL & environment configuration
 * - Bearer JWT injection
 * - Content-Type / Accept headers
 * - Universal envelope unwrapping ({ success, data, error, meta })
 * - HTTP status code classification
 * - HTTP 204 No Content handling
 * - Normalized ApiClientError with error codes and request IDs
 * - Unauthorized (401) callback hook for session eviction
 */

import { Envelope, Meta } from '../types/contract';

export class ApiClientError extends Error {
  code: string;
  status: number;
  requestId?: string;
  data?: unknown;

  constructor(
    message: string,
    code: string,
    status: number,
    requestId?: string,
    data?: unknown
  ) {
    super(message);
    this.name = 'ApiClientError';
    this.code = code;
    this.status = status;
    this.requestId = requestId;
    this.data = data;
  }
}

export interface ApiResponse<T> {
  data: T;
  meta: Meta;
}

type UnauthorizedHandler = () => void;

class ApiClient {
  private baseUrl: string;
  private token: string | null = null;
  private unauthorizedHandlers: Set<UnauthorizedHandler> = new Set();

  constructor() {
    const envUrl = import.meta.env.VITE_API_BASE_URL;
    // Default to http://localhost:8000 if not configured
    this.baseUrl = (envUrl || 'http://localhost:8000').replace(/\/+$/, '');
  }

  public setToken(token: string | null): void {
    this.token = token;
  }

  public getToken(): string | null {
    return this.token;
  }

  public onUnauthorized(handler: UnauthorizedHandler): () => void {
    this.unauthorizedHandlers.add(handler);
    return () => this.unauthorizedHandlers.delete(handler);
  }

  private notifyUnauthorized(): void {
    for (const handler of this.unauthorizedHandlers) {
      try {
        handler();
      } catch (err) {
        console.error('Error in onUnauthorized handler:', err);
      }
    }
  }

  /**
   * Core request method. Normalizes path with /api/v1 prefix.
   */
  public async request<T = unknown>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    // Ensure leading slash and /api/v1 prefix
    const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const path = cleanEndpoint.startsWith('/api/v1')
      ? cleanEndpoint
      : `/api/v1${cleanEndpoint}`;

    const url = `${this.baseUrl}${path}`;

    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');

    // Attach Bearer token if available
    if (this.token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${this.token}`);
    }

    // Set Content-Type to application/json if sending a body and not FormData
    if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    let response: Response;
    try {
      response = await fetch(url, {
        ...options,
        headers,
      });
    } catch (networkErr: unknown) {
      const msg = networkErr instanceof Error ? networkErr.message : 'Network request failed';
      throw new ApiClientError(
        `Unable to connect to CyberSec AI backend (${this.baseUrl}). ${msg}`,
        'NETWORK_ERROR',
        0
      );
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return {
        data: undefined as unknown as T,
        meta: { request_id: response.headers.get('x-request-id') || '' },
      };
    }

    // Parse JSON envelope
    let json: Envelope<T> | null = null;
    try {
      json = (await response.json()) as Envelope<T>;
    } catch {
      if (!response.ok) {
        throw new ApiClientError(
          `Server returned HTTP ${response.status} with non-JSON response.`,
          'INTERNAL_ERROR',
          response.status
        );
      }
      throw new ApiClientError(
        'Malformed JSON response from server.',
        'VALIDATION_ERROR',
        response.status
      );
    }

    // Handle 401 Unauthorized
    if (response.status === 401) {
      this.notifyUnauthorized();
      const code = json?.error?.code || 'INVALID_CREDENTIALS';
      const message = json?.error?.message || 'Authentication required or session expired.';
      throw new ApiClientError(message, code, 401, json?.meta?.request_id);
    }

    // Check envelope success or HTTP failure
    if (!response.ok || !json.success) {
      const code = json?.error?.code || this.mapStatusToErrorCode(response.status);
      const message =
        json?.error?.message ||
        `Request failed with status ${response.status} (${response.statusText})`;
      throw new ApiClientError(message, code, response.status, json?.meta?.request_id, json?.data);
    }

    return {
      data: json.data as T,
      meta: json.meta,
    };
  }

  public async get<T>(path: string, options: RequestInit = {}): Promise<T> {
    const res = await this.request<T>(path, { ...options, method: 'GET' });
    return res.data;
  }

  public async getWithMeta<T>(path: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
    return this.request<T>(path, { ...options, method: 'GET' });
  }

  public async post<T>(path: string, body?: unknown, options: RequestInit = {}): Promise<T> {
    const res = await this.request<T>(path, {
      ...options,
      method: 'POST',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    return res.data;
  }

  public async patch<T>(path: string, body?: unknown, options: RequestInit = {}): Promise<T> {
    const res = await this.request<T>(path, {
      ...options,
      method: 'PATCH',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    return res.data;
  }

  public async delete<T = void>(path: string, options: RequestInit = {}): Promise<T> {
    const res = await this.request<T>(path, { ...options, method: 'DELETE' });
    return res.data;
  }

  private mapStatusToErrorCode(status: number): string {
    switch (status) {
      case 400:
        return 'VALIDATION_ERROR';
      case 401:
        return 'INVALID_CREDENTIALS';
      case 403:
        return 'TARGET_NOT_AUTHORIZED';
      case 404:
        return 'PROJECT_NOT_FOUND';
      case 409:
        return 'SCAN_ALREADY_RUNNING';
      case 422:
        return 'VALIDATION_ERROR';
      case 503:
        return 'DATABASE_ERROR';
      default:
        return 'INTERNAL_ERROR';
    }
  }
}

export const apiClient = new ApiClient();
