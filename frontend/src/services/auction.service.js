import axiosClient from "@/utils/axios.js";

const AUCTION_API = {
    CREATE_AUCTION: '/api/auctions',
    GET_AUCTIONS: '/api/auctions',
    GET_AUCTION_BY_ID: '/api/auctions',
    GET_MY_AUCTIONS: '/api/auctions/my-auctions',
    ADD_TO_WATCHLIST: '/api/auctions/add-to-watchlist',
    REMOVE_FROM_WATCHLIST: '/api/auctions/remove-from-watchlist',
    GET_WATCHLIST: '/api/auctions/watchlist',
    CANCEL_AUCTION: '/api/auctions/cancel',
    REOPEN_AUCTION: '/api/auctions/reopen',
};

export const auctionService = {
    // Create auction
    createAuction: async (auctionData) => {
        try {
            const response = await axiosClient.post(AUCTION_API.CREATE_AUCTION, auctionData);
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Auction creation failed',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Get auctions with search/filter
    getAuctions: async (searchParams = {}) => {
        try {
            const response = await axiosClient.get(AUCTION_API.GET_AUCTIONS, {
                params: searchParams
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

    // Get auction by ID
    getAuctionById: async (auctionId) => {
        try {
            const response = await axiosClient.get(`${AUCTION_API.GET_AUCTION_BY_ID}/${auctionId}`);
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to fetch auction',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Add auction to watchlist
    addToWatchlist: async (auctionId) => {
        try {
            const response = await axiosClient.post(AUCTION_API.ADD_TO_WATCHLIST, {
                auctionId
            });
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to add to watchlist',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Remove auction from watchlist
    removeFromWatchlist: async (auctionId) => {
        try {
            const response = await axiosClient.post(AUCTION_API.REMOVE_FROM_WATCHLIST, {
                auctionId
            });
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to remove from watchlist',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Get user's watchlist
    getWatchlist: async () => {
        try {
            const response = await axiosClient.post(AUCTION_API.GET_WATCHLIST);
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to fetch watchlist',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Get seller's auctions
    getMyAuctions: async () => {
        try {
            const response = await axiosClient.get(AUCTION_API.GET_MY_AUCTIONS);
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to fetch my auctions',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Cancel auction
    cancelAuction: async (auctionId, reason) => {
        try {
            const response = await axiosClient.patch(`${AUCTION_API.CANCEL_AUCTION}`, {
                auctionId,
                reason
            });
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to cancel auction',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Reopen auction
    reopenAuction: async (auctionId) => {
        try {
            const response = await axiosClient.patch(AUCTION_API.REOPEN_AUCTION, {
                auctionId
            });
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to reopen auction',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    }
};
