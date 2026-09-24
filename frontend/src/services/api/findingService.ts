/**
 * Findings Service for Sentinel AI backend (/api/v1/scans/{id}/findings & /findings/{id})
 */

import { apiClient } from '../apiClient';
import {
  FindingOut,
  FindingStatus,
  Severity,
  PageData,
} from '../../types/contract';

export interface ListFindingsParams {
  page?: number;
  pageSize?: number;
  severity?: Severity;
  status?: FindingStatus;
}

export const findingService = {
  /**
   * List paginated findings for a specific scan with optional severity/status filters.
   */
  async listFindingsForScan(
    scanId: string,
    params: ListFindingsParams = {}
  ): Promise<{ items: FindingOut[]; total: number }> {
    const searchParams = new URLSearchParams();
    if (params.page) searchParams.set('page', String(params.page));
    if (params.pageSize) searchParams.set('page_size', String(params.pageSize));
    if (params.severity) searchParams.set('severity', params.severity);
    if (params.status) searchParams.set('status', params.status);

    const query = searchParams.toString();
    const endpoint = `/scans/${scanId}/findings${query ? `?${query}` : ''}`;

    const res = await apiClient.getWithMeta<PageData<FindingOut>>(endpoint);
    return {
      items: res.data.items,
      total: res.meta.total ?? res.data.items.length,
    };
  },

  /**
   * Fetch single finding by UUID.
   */
  async getFinding(findingId: string): Promise<FindingOut> {
    return apiClient.get<FindingOut>(`/findings/${findingId}`);
  },
};
