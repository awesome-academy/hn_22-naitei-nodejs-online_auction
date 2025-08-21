import axiosClient from "@/utils/axios.js";

const STATISTICS_API = {
    SELLER_STATS: '/api/statistics/seller',
};

export const statisticsService = {
    getSellerStatistics: async (params = {}) => {
        try {
            // Remove undefined, null, empty string values and NaN values
            const cleanParams = {};
            Object.keys(params).forEach(key => {
                const value = params[key];
                if (value !== undefined &&
                    value !== null &&
                    value !== '' &&
                    !Number.isNaN(value)) {
                    cleanParams[key] = value;
                }
            });

            const response = await axiosClient.get(STATISTICS_API.SELLER_STATS, {
                params: cleanParams
            });
            return response.data;
        } catch (err) {
            const { statusCode, message, errorCode } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || err?.response?.status || 500,
                message: message || 'Failed to fetch seller statistics',
                errorCode: errorCode || 'FETCH_STATISTICS_ERROR',
            });
        }
    },
};
