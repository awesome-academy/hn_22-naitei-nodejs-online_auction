import axiosClient from '@/utils/axios.js';

const USER_MANAGEMENT_API = {
  GET_USERS: '/api/users',
  CREATE_WARNING: (userId) => `/api/users/warnings/${userId}`,
  GET_USER_WARNINGS: (userId) => `/api/users/warnings/${userId}`,
  REMOVE_WARNING: (warningId) => `/api/users/warnings/${warningId}`,
  BAN_USER: (userId) => `/api/users/ban/${userId}`,
  UNBAN_USER: (userId) => `/api/users/unban/${userId}`,
};

export const userManagementService = {
  // Get users with pagination support
  listUsers: async (role, page = 1, limit = 10) => {
    try {
      const params = new URLSearchParams();
      if (role) params.append('role', role);
      params.append('page', page.toString());
      params.append('limit', limit.toString());

      const response = await axiosClient.get(`${USER_MANAGEMENT_API.GET_USERS}?${params.toString()}`);
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to get users'
          }
        },
        message: message || 'Failed to get users',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  // Get users by role (BIDDER or SELLER) - backward compatibility
  getUsersByRole: async (role, page = 1, limit = 10) => {
    return userManagementService.listUsers(role, page, limit);
  },

  // Create warning for user
  createWarning: async (userId, warningData) => {
    try {
      const response = await axiosClient.post(
        USER_MANAGEMENT_API.CREATE_WARNING(userId),
        warningData
      );
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to create warning'
          }
        },
        message: message || 'Failed to create warning',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  // Get user warnings
  getUserWarnings: async (userId) => {
    try {
      const response = await axiosClient.get(USER_MANAGEMENT_API.GET_USER_WARNINGS(userId));
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to get user warnings'
          }
        },
        message: message || 'Failed to get user warnings',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  // Remove warning
  removeWarning: async (warningId) => {
    try {
      const response = await axiosClient.delete(USER_MANAGEMENT_API.REMOVE_WARNING(warningId));
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to remove warning'
          }
        },
        message: message || 'Failed to remove warning',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  // Ban user
  banUser: async (userId) => {
    try {
      const url = USER_MANAGEMENT_API.BAN_USER(userId);

      const response = await axiosClient.post(url);

      return response.data;
    } catch (err) {

      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to ban user'
          }
        },
        message: message || 'Failed to ban user',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  // Unban user - FIX THIS
  unbanUser: async (userId) => {
    try {
      const url = USER_MANAGEMENT_API.UNBAN_USER(userId);
      const response = await axiosClient.post(url);

      return response.data;
    } catch (err) {

      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to unban user'
          }
        },
        message: message || 'Failed to unban user',
        statusCode: err?.response?.status || 500,
      };
    }
  },
};

export const userManagement = userManagementService;
