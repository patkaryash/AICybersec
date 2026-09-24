/**
 * Dashboard Service for Sentinel AI backend (/api/v1/dashboard)
 */

import { apiClient } from '../apiClient';
import { DashboardOut } from '../../types/contract';

export const dashboardService = {
  /**
   * Fetch aggregate security statistics and recent scans visible to current user.
   */
  async getDashboard(recentLimit = 6): Promise<DashboardOut> {
    return apiClient.get<DashboardOut>(`/dashboard?recent_limit=${recentLimit}`);
  },
};
