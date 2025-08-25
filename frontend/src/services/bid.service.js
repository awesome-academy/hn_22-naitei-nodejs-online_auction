import axiosClient from "@/utils/axios.js";

const BID_API = {
  PLACE_BID: "/api/bid",
  PLACE_HIDDEN: "/api/bid/hidden",
  GET_BIDS: "/api/bid",
};

export const bidService = {
  placeBid: async ({ auctionId, bidAmount }) => {
    try {
      const res = await axiosClient.post(BID_API.PLACE_BID, { auctionId, bidAmount });
      return res.data;
    } catch (err) {
      // Extract detailed error information from backend
      const statusCode = err?.response?.status || err?.status || 500;
      const backendData = err?.response?.data || {};

      return Promise.reject({
        statusCode,
        message: backendData.message || 'Place bid failed',
        errorCode: backendData.errorCode || 'INTERNAL_SERVER_ERROR',
        response: err?.response,
        originalError: err
      });
    }
  },

  placeHiddenBids: async ({ auctionId, bidAmounts }) => {
    try {
      const res = await axiosClient.post(BID_API.PLACE_HIDDEN, { auctionId, bidAmounts });
      return res.data;
    } catch (err) {
      // Extract detailed error information from backend
      const statusCode = err?.response?.status || err?.status || 500;
      const backendData = err?.response?.data || {};

      return Promise.reject({
        statusCode,
        message: backendData.message || 'Place hidden bids failed',
        errorCode: backendData.errorCode || 'INTERNAL_SERVER_ERROR',
        response: err?.response,
        originalError: err
      });
    }
  },

  getBids: async (auctionId) => {
    try {
      const res = await axiosClient.get(`${BID_API.GET_BIDS}/${auctionId}`);
      return res.data;
    } catch (err) {
      // Extract detailed error information from backend
      const statusCode = err?.response?.status || err?.status || 500;
      const backendData = err?.response?.data || {};

      return Promise.reject({
        statusCode,
        message: backendData.message || 'Get bids failed',
        errorCode: backendData.errorCode || 'INTERNAL_SERVER_ERROR',
        response: err?.response,
        originalError: err
      });
    }
  },
};
