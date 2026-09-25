/**
 * Events Service for CyberSec AI backend (/api/v1/scans/{id}/agent-events & /tool-runs)
 */

import { apiClient } from '../apiClient';
import {
  AgentEventOut,
  ToolRunOut,
  PageData,
} from '../../types/contract';

export const eventService = {
  /**
   * Fetch agent events using cursor pagination.
   * Pass afterId (the last observed seq) to get subsequent events.
   * afterId=0 replays from the beginning.
   */
  async listAgentEvents(
    scanId: string,
    afterId = 0,
    limit = 50
  ): Promise<AgentEventOut[]> {
    const res = await apiClient.get<PageData<AgentEventOut>>(
      `/scans/${scanId}/agent-events?after_id=${afterId}&limit=${limit}`
    );
    return res.items;
  },

  /**
   * Fetch paginated tool runs for a scan, oldest first.
   */
  async listToolRuns(
    scanId: string,
    page = 1,
    pageSize = 20
  ): Promise<{ items: ToolRunOut[]; total: number }> {
    const res = await apiClient.getWithMeta<PageData<ToolRunOut>>(
      `/scans/${scanId}/tool-runs?page=${page}&page_size=${pageSize}`
    );
    return {
      items: res.data.items,
      total: res.meta.total ?? res.data.items.length,
    };
  },
};
