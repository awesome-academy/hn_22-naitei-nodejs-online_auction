import axiosClient from "@/utils/axios.js";

const ORDER_API = {
  GET_ORDERS: '/api/orders',
};

// Transform frontend sortBy values to backend enum values
const transformSortByValue = (sortBy) => {
  const sortByMap = {
    'createdAt': 'CREATED_AT',
    'updatedAt': 'UPDATED_AT',
    'totalAmount': 'TOTAL_AMOUNT'
  };
  return sortByMap[sortBy] || 'CREATED_AT';
};

export const orderService = {
  getOrders: async (params = {}) => {
    try {
      // Transform sortBy values to match backend enum
      const transformedParams = {
        page: params.page || 1,
        limit: params.limit || 10,
        status: params.status || undefined,
        sortBy: transformSortByValue(params.sortBy || 'createdAt'),
        sortOrder: params.sortOrder || 'desc',
        search: params.search || undefined,
        ...params
      };

      // Remove undefined values to avoid sending empty query params
      Object.keys(transformedParams).forEach(key => {
        if (transformedParams[key] === undefined || transformedParams[key] === '') {
          delete transformedParams[key];
        }
      });

      const response = await axiosClient.get(ORDER_API.GET_ORDERS, {
        params: transformedParams
      });
      return response.data;
    } catch (err) {
      const { statusCode, message, errorCode } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || err?.response?.status || 500,
        message: message || 'Failed to fetch orders',
        errorCode: errorCode || 'FETCH_ORDERS_ERROR',
      });
    }
  },

  getOrderById: async (orderId) => {
    try {
      const response = await axiosClient.get(`${ORDER_API.GET_ORDERS}/${orderId}`);
      return response.data;
    } catch (err) {
      const { statusCode, message, errorCode } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || err?.response?.status || 500,
        message: message || 'Failed to fetch order details',
        errorCode: errorCode || 'FETCH_ORDER_ERROR',
      });
    }
  },

  updateOrderStatus: async (orderId, status) => {
    try {
      const response = await axiosClient.patch(`${ORDER_API.GET_ORDERS}/${orderId}/status`, {
        status
      });
      return response.data;
    } catch (err) {
      const { statusCode, message, errorCode } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || err?.response?.status || 500,
        message: message || 'Failed to update order status',
        errorCode: errorCode || 'UPDATE_ORDER_ERROR',
      });
    }
  },

  cancelOrder: async (orderId, reason) => {
    try {
      const response = await axiosClient.patch(`${ORDER_API.GET_ORDERS}/${orderId}/cancel`, {
        reason
      });
      return response.data;
    } catch (err) {
      const { statusCode, message, errorCode } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || err?.response?.status || 500,
        message: message || 'Failed to cancel order',
        errorCode: errorCode || 'CANCEL_ORDER_ERROR',
      });
    }
  },

  confirmShipped: async (orderId, trackingNumber = '') => {
    try {
      const response = await axiosClient.patch(`${ORDER_API.GET_ORDERS}/${orderId}/confirm-shipped`, {
        trackingNumber: trackingNumber || undefined
      });
      return response.data;
    } catch (err) {
      const { statusCode, message, errorCode } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || err?.response?.status || 500,
        message: message || 'Failed to confirm shipment',
        errorCode: errorCode || 'CONFIRM_SHIPPED_ERROR',
      });
    }
  }
};
