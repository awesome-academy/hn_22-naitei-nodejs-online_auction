import axios from 'axios';
import axiosClient from "@/utils/axios.js";

const AUTH_API = {
  LOGIN: '/api/users/login',
  REFRESH_TOKEN: 'api/users/refresh-token',
  CHANGE_PASSWORD: '/api/users/changePassword',
};

export const authService = {
  refreshToken: async (tokenPayload) => {
    try {
      const response = await axios.post(
        AUTH_API.REFRESH_TOKEN,
        tokenPayload,
        {
          baseURL: import.meta.env.VITE_BACKEND_URL,
          headers: { 'Content-Type': 'application/json' },
          withCredentials: true,
          timeout: 10000,
        }
      );
      return response.data;
    } catch (err) {
      const { statusCode, message, errorCode } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || err?.response?.status || 500,
        message: message || 'Failed to refresh token',
        errorCode: errorCode || 'INTERNAL_SERVER_ERROR',
      });
    }
  },

  login: async (credentials) => {
    try {
      const response = await axiosClient.post(
        AUTH_API.LOGIN,
        credentials
      );
      return response.data;
    } catch (err) {
      const statusCode = err?.status;
      const { message, code } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || 500,
        message: message || 'LoginForm failed',
        errorCode: code || 'INTERNAL_SERVER_ERROR',
      });
    }
  },

  changePassword: async (passwordData) => {
    try {
      const response = await axiosClient.put(
        AUTH_API.CHANGE_PASSWORD,
        passwordData
      );
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to change password'
          }
        },
        message: message || 'Failed to change password',
        statusCode: err?.response?.status || 500,
      };
    }
  }
};
