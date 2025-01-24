import axios from 'axios';
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface AuthState {
  token: string | null;
  user: {
    userId: string;
    tenantId: string;
    roles: string[];
  } | null;
  login: (email: string, password: string, tenantId: string) => Promise<void>;
  register: (email: string, password: string, tenantId: string) => Promise<void>;
  logout: () => Promise<void>;
}

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
});

export const useAuth = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      user: null,
      login: async (email, password, tenantId) => {
        const response = await api.post('/auth/login', {
          email,
          password,
          tenantId,
        });
        const { token } = response.data;
        const user = JSON.parse(atob(token.split('.')[1]));
        set({ token, user });
      },
      register: async (email, password, tenantId) => {
        const response = await api.post('/auth/register', {
          email,
          password,
          tenantId,
        });
        const { token } = response.data;
        const user = JSON.parse(atob(token.split('.')[1]));
        set({ token, user });
      },
      logout: async () => {
        await api.post('/auth/logout');
        set({ token: null, user: null });
      },
    }),
    {
      name: 'auth-storage',
    }
  )
);

// Axios interceptor for adding token to requests
api.interceptors.request.use((config) => {
  const { token } = useAuth.getState();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const useIsAuthenticated = () => {
  const token = useAuth((state) => state.token);
  return !!token;
};

export const useUserRoles = () => {
  const user = useAuth((state) => state.user);
  return user?.roles || [];
};

export const useHasRole = (role: string) => {
  const roles = useUserRoles();
  return roles.includes(role);
};