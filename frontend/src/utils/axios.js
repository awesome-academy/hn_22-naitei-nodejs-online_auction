import axios from "axios";
import {getAccessToken, getRefreshToken, setAccessToken, setRefreshToken, clearTokens, clearUser} from '@/utils/token-storage.js';
import {authService} from "@/services/auth.service.js";

const RETRY_ERROR_CODES = new Set([
  'ACCESS_TOKEN_EXPIRED',
  'INVALID_ACCESS_TOKEN',
  'UNKNOWN_ACCESS_TOKEN',
  'MISSING_AUTH_HEADER',
]);

const FORCE_LOGOUT_CODES = new Set([
  'REFRESH_TOKEN_EXPIRED',
  'INVALID_REFRESH_TOKEN',
  'UNKNOWN_REFRESH_TOKEN',
  'INTERNAL_SERVER_ERROR',
]);

const axiosClient = axios.create({
  baseURL: import.meta.env.VITE_BACKEND_URL,
  headers: { "Content-Type": "application/json" },
  withCredentials: true,
  timeout: 10000,
})

axiosClient.interceptors.request.use(
  (config) => {
    const token = getAccessToken();
    if (token) config.headers['Authorization'] = `Bearer ${token}`;
    return config;
  },
  (error) => Promise.reject(error)
)

axiosClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const errorCode = error.response?.data?.errorCode;

    const shouldAttemptRefresh = !originalRequest?._retry && RETRY_ERROR_CODES.has(errorCode);
    const forceLogout = FORCE_LOGOUT_CODES.has(errorCode);

    if (shouldAttemptRefresh) {
      originalRequest._retry = true;

      try {
        const refreshToken = getRefreshToken();
        if (!refreshToken) {
          return Promise.reject({
            statusCode: null,
            message: "No refresh token available",
            errorCode: 'NO_REFRESH_TOKEN',
          });
        }

        const response = await authService.refreshToken({ "refreshToken": refreshToken });
        const newAccessToken = response?.data?.accessToken;
        const newRefreshToken = response?.data?.refreshToken;
        if (!newAccessToken || !newRefreshToken) {
          return Promise.reject({
            statusCode: null,
            message: "Invalid tokens received from refresh API",
            errorCode: 'INVALID_TOKEN_RESPONSE',
          });
        }

        setAccessToken(newAccessToken);
        setRefreshToken(newRefreshToken);
        originalRequest.headers['Authorization'] = `Bearer ${newAccessToken}`;
        return axiosClient(originalRequest);
      } catch (err) {
        clearTokens();
        window.location.href = '/login';
        return Promise.reject(err);
      }
    }

    if (forceLogout) {
      clearTokens();
      clearUser();
      window.location.href = '/login';
      return Promise.reject(error);
    }

    return Promise.reject(error);
  }
)

export default axiosClient;
