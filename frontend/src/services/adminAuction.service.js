import axiosClient from "@/utils/axios.js";

const ADMIN_AUCTION_API = {
    GET_AUCTIONS: '/api/auctions',
    GET_AUCTION_DETAIL: '/api/auctions',
    CONFIRM_AUCTION: '/api/auctions/open',
};

export const adminAuctionService = {
    // Get all auctions for admin management
    getAuctions: async (searchParams = {}) => {
        try {
            // Convert our parameters to match the API expectations
            const apiParams = {
                ...searchParams,
                // Convert limit to size
                size: searchParams.limit || 10,
                // Convert sortBy to sortField
                sortField: searchParams.sortBy || 'createdAt',
                // Convert sortOrder to sortDirection (lowercase)
                // Convert sortOrder to sortDirection
                sortDirection: searchParams.sortOrder?.toLowerCase() || 'desc',
            };

            // Remove the old parameter names to avoid conflicts
            delete apiParams.limit;
            delete apiParams.sortBy;
            delete apiParams.sortOrder;

            const response = await axiosClient.get(ADMIN_AUCTION_API.GET_AUCTIONS, {
                params: apiParams
            });
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to fetch auctions',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Get auction details by ID
    getAuctionById: async (auctionId) => {
        try {
            const response = await axiosClient.get(`${ADMIN_AUCTION_API.GET_AUCTION_DETAIL}/${auctionId}`);
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to fetch auction details',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Confirm/Open auction (Admin only)
    confirmAuction: async (auctionId) => {
        try {
            const response = await axiosClient.patch(`${ADMIN_AUCTION_API.CONFIRM_AUCTION}/${auctionId}`);
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to confirm auction',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },
};
