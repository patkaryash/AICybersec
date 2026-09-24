/**
 * Scans Service for Sentinel AI backend (/api/v1/scans)
 */

import { apiClient } from '../apiClient';
import {
  ScanCreate,
  ScanOut,
  ScanStatus,
  PageData,
} from '../../types/contract';

export interface ListScansParams {
  page?: number;
  pageSize?: number;
  projectId?: string;
  status?: ScanStatus;
}

export const scanService = {
  /**
   * Create and persist a new scan record with status="queued".
   * Returns HTTP 202 with ScanOut.
   */
  async createScan(data: ScanCreate): Promise<ScanOut> {
    return apiClient.post<ScanOut>('/scans', data);
  },

  /**
   * List paginated scans filtered optionally by project_id and status.
   */
  async listScans(
    params: ListScansParams = {}
  ): Promise<{ items: ScanOut[]; total: number }> {
    const searchParams = new URLSearchParams();
    if (params.page) searchParams.set('page', String(params.page));
    if (params.pageSize) searchParams.set('page_size', String(params.pageSize));
    if (params.projectId) searchParams.set('project_id', params.projectId);
    if (params.status) searchParams.set('status', params.status);

    const query = searchParams.toString();
    const endpoint = `/scans${query ? `?${query}` : ''}`;

    const res = await apiClient.getWithMeta<PageData<ScanOut>>(endpoint);
    return {
      items: res.data.items,
      total: res.meta.total ?? res.data.items.length,
    };
  },

  /**
   * Fetch single scan details by UUID.
   */
  async getScan(scanId: string): Promise<ScanOut> {
    return apiClient.get<ScanOut>(`/scans/${scanId}`);
  },

  /**
   * Cancel an active or queued scan.
   * Returns HTTP 202 with updated ScanOut.
   */
  async cancelScan(scanId: string): Promise<ScanOut> {
    return apiClient.post<ScanOut>(`/scans/${scanId}/cancel`);
  },
};
