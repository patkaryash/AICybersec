/**
 * Assets Service for CyberSec AI backend (/api/v1/scans/{id}/assets & /assets/{id})
 */

import { apiClient } from '../apiClient';
import {
  AssetOut,
  AssetType,
  PageData,
} from '../../types/contract';

export interface ListAssetsParams {
  page?: number;
  pageSize?: number;
  assetType?: AssetType;
}

export const assetService = {
  /**
   * List paginated discovered assets for a scan.
   */
  async listAssetsForScan(
    scanId: string,
    params: ListAssetsParams = {}
  ): Promise<{ items: AssetOut[]; total: number }> {
    const searchParams = new URLSearchParams();
    if (params.page) searchParams.set('page', String(params.page));
    if (params.pageSize) searchParams.set('page_size', String(params.pageSize));
    if (params.assetType) searchParams.set('asset_type', params.assetType);

    const query = searchParams.toString();
    const endpoint = `/scans/${scanId}/assets${query ? `?${query}` : ''}`;

    const res = await apiClient.getWithMeta<PageData<AssetOut>>(endpoint);
    return {
      items: res.data.items,
      total: res.meta.total ?? res.data.items.length,
    };
  },

  /**
   * Fetch single asset by UUID.
   */
  async getAsset(assetId: string): Promise<AssetOut> {
    return apiClient.get<AssetOut>(`/assets/${assetId}`);
  },
};
