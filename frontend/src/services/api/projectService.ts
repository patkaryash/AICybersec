/**
 * Project Service for Sentinel AI backend (/api/v1/projects)
 */

import { apiClient } from '../apiClient';
import {
  ProjectCreate,
  ProjectOut,
  ProjectUpdate,
  PageData,
} from '../../types/contract';

export const projectService = {
  async createProject(data: ProjectCreate): Promise<ProjectOut> {
    return apiClient.post<ProjectOut>('/projects', data);
  },

  async listProjects(
    page = 1,
    pageSize = 20
  ): Promise<{ items: ProjectOut[]; total: number }> {
    const res = await apiClient.getWithMeta<PageData<ProjectOut>>(
      `/projects?page=${page}&page_size=${pageSize}`
    );
    return {
      items: res.data.items,
      total: res.meta.total ?? res.data.items.length,
    };
  },

  async getProject(projectId: string): Promise<ProjectOut> {
    return apiClient.get<ProjectOut>(`/projects/${projectId}`);
  },

  async updateProject(
    projectId: string,
    data: ProjectUpdate
  ): Promise<ProjectOut> {
    return apiClient.patch<ProjectOut>(`/projects/${projectId}`, data);
  },

  async deleteProject(projectId: string): Promise<void> {
    await apiClient.delete(`/projects/${projectId}`);
  },
};
