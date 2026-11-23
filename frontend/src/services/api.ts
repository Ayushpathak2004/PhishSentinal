import axios from 'axios';
import { 
  ScanResult, 
  DashboardStats, 
  AgentStatus, 
  IncidentItem, 
  QuarantinedItem,
  MlModelMetrics,
} from '../types';

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
});

// Attach a bearer token when one has been stored by the login page.
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('phishsentinel_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const authApi = {
  login: async (username: string, password: string) => {
    const res = await api.post<{ access_token: string; token_type: string }>('/auth/login', {
      username,
      password
    });
    localStorage.setItem('phishsentinel_token', res.data.access_token);
    return res.data;
  },
  logout: () => localStorage.removeItem('phishsentinel_token'),
  isAuthenticated: () => Boolean(localStorage.getItem('phishsentinel_token')),
  me: async () => {
    const res = await api.get('/auth/me');
    return res.data;
  }
};

export const scanApi = {
  scanEmail: async (data: { raw_content?: string; sender?: string; subject?: string; body?: string } | FormData) => {
    if (data instanceof FormData) {
      const res = await api.post<ScanResult>('/scan/email', data, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      return res.data;
    }
    const res = await api.post<ScanResult>('/scan/email', data);
    return res.data;
  },

  scanWebsite: async (url: string) => {
    const res = await api.post<ScanResult>('/scan/website', { url });
    return res.data;
  },

  scanQR: async (data: { image_base64?: string; manual_content?: string } | FormData) => {
    if (data instanceof FormData) {
      const res = await api.post<ScanResult>('/scan/qr', data, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      return res.data;
    }
    const res = await api.post<ScanResult>('/scan/qr', data);
    return res.data;
  },

  getScans: async (params?: { scan_type?: string; risk_level?: string; limit?: number }) => {
    const res = await api.get<{ total: number; items: any[] }>('/scans', { params });
    return res.data;
  },

  getScanById: async (id: string) => {
    const res = await api.get<ScanResult>(`/scans/${id}`);
    return res.data;
  },
};

export const dashboardApi = {
  getStats: async () => {
    const res = await api.get<DashboardStats>('/dashboard/stats');
    return res.data;
  },
  getActivity: async () => {
    const res = await api.get<any[]>('/dashboard/activity');
    return res.data;
  },
};

export const agentsApi = {
  getStatus: async () => {
    const res = await api.get<AgentStatus[]>('/agents');
    return res.data;
  },
  getActivity: async () => {
    const res = await api.get<any[]>('/agents/activity');
    return res.data;
  },
};

export const mlApi = {
  getMetrics: async () => {
    const res = await api.get<{ models: MlModelMetrics[] }>('/ml/metrics');
    return res.data;
  },
};

export const incidentsApi = {
  getIncidents: async (params?: { severity?: string; status?: string }) => {
    const res = await api.get<{ total: number; items: IncidentItem[] }>('/incidents', { params });
    return res.data;
  },
  getIncidentById: async (id: string) => {
    const res = await api.get<any>(`/incidents/${id}`);
    return res.data;
  },
  updateIncident: async (id: string, data: { status?: string; resolution_notes?: string; assigned_action?: string }) => {
    const res = await api.patch<any>(`/incidents/${id}`, data);
    return res.data;
  },
};

export const quarantineApi = {
  getFiles: async (status?: string) => {
    const res = await api.get<QuarantinedItem[]>('/quarantine', { params: { status } });
    return res.data;
  },
  verifyIntegrity: async (id: string) => {
    const res = await api.get<any>(`/quarantine/${id}/verify`);
    return res.data;
  },
  restoreFile: async (id: string, data: { authorized_by: string; reason: string }) => {
    const res = await api.post<any>(`/quarantine/${id}/restore`, data);
    return res.data;
  },
};

export const reportsApi = {
  getSummary: async () => {
    const res = await api.get<any>('/reports');
    return res.data;
  },
  getPdfUrl: (scanId: string) => `/api/reports/${scanId}/pdf`,
  getCsvExportUrl: () => `/api/reports/export/csv`,
};

export const settingsApi = {
  getSettings: async () => {
    const res = await api.get<any>('/settings');
    return res.data;
  },
  updateSettings: async (data: any) => {
    const res = await api.post<any>('/settings', data);
    return res.data;
  },
  getThreatIntel: async () => {
    const res = await api.get<any>('/threat-intel');
    return res.data;
  },
};

export default api;
