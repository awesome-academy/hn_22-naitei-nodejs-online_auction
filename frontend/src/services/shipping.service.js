import axiosClient from "@/utils/axios.js";

const SHIPPING_API = {
  GET_BIDDER_SHIPPINGS: '/api/shipping/bidder',
  GET_SELLER_SHIPPINGS: '/api/shipping/seller',
  CONFIRM_DELIVERY: (shippingId) => `/api/shipping/${shippingId}/confirm-delivery`,
};

const transformSortByValue = (sortBy) => {
  const sortByMap = {
    'createdAt': 'CREATED_AT',
    'updatedAt': 'UPDATED_AT',
    'shippedAt': 'SHIPPED_AT',
    'estimatedDelivery': 'ESTIMATED_DELIVERY',
    'actualDelivery': 'ACTUAL_DELIVERY'
  };
  return sortByMap[sortBy] || 'CREATED_AT';
};

// Shared helper function to transform and clean shipping params
const transformShippingParams = (params = {}) => {
  const transformedParams = {
    page: params.page || 1,
    limit: params.limit || 10,
    status: params.status || undefined,
    sortBy: transformSortByValue(params.sortBy || 'createdAt'),
    sortOrder: params.sortOrder || 'desc',
    search: params.search || undefined,
    ...params
  };

  Object.keys(transformedParams).forEach(key => {
    if (transformedParams[key] === undefined || transformedParams[key] === '') {
      delete transformedParams[key];
    }
  });

  return transformedParams;
};

const handleShippingError = (err) => {
  const { statusCode, message, errorCode } = err?.response?.data || {};
  return Promise.reject({
    statusCode: statusCode || err?.response?.status || 500,
    message: message || 'Failed to fetch shippings',
    errorCode: errorCode || 'FETCH_SHIPPINGS_ERROR',
  });
};

export const shippingService = {
  getBidderShippings: async (params = {}) => {
    try {
      const transformedParams = transformShippingParams(params);

      const response = await axiosClient.get(SHIPPING_API.GET_BIDDER_SHIPPINGS, {
        params: transformedParams
      });
      return response.data;
    } catch (err) {
      return handleShippingError(err);
    }
  },

  getSellerShippings: async (params = {}) => {
    try {
      const transformedParams = transformShippingParams(params);

      const response = await axiosClient.get(SHIPPING_API.GET_SELLER_SHIPPINGS, {
        params: transformedParams
      });
      return response.data;
    } catch (err) {
      return handleShippingError(err);
    }
  },

  confirmDelivery: async (shippingId) => {
    try {
      const response = await axiosClient.patch(SHIPPING_API.CONFIRM_DELIVERY(shippingId));
      return response.data;
    } catch (err) {
      const { statusCode, message, errorCode } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || err?.response?.status || 500,
        message: message || 'Failed to confirm delivery',
        errorCode: errorCode || 'CONFIRM_DELIVERY_ERROR',
      });
    }
  },
};
