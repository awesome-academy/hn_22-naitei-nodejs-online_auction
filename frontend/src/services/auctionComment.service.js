import axiosClient from "@/utils/axios.js";

const AUCTION_COMMENT_API = {
    GET_COMMENTS: (auctionId) => `/api/auction-comments/auction/${auctionId}`,
    CREATE_COMMENT: '/api/auction-comments',
    UPDATE_COMMENT: (commentId) => `/api/auction-comments/${commentId}`,
    DELETE_COMMENT: (commentId) => `/api/auction-comments/${commentId}`,
    GET_COMMENT: (commentId) => `/api/auction-comments/${commentId}`,
    GET_USER_COMMENTS: (userId) => `/api/auction-comments/user/${userId}`,
};

export const auctionCommentService = {
    // Get comments by auction ID
    getCommentsByAuctionId: async (auctionId, page = 1, limit = 10) => {
        try {
            const response = await axiosClient.get(AUCTION_COMMENT_API.GET_COMMENTS(auctionId), {
                params: { page, limit }
            });
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to fetch auction comments',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Create auction comment
    createComment: async (commentData) => {
        try {
            const response = await axiosClient.post(AUCTION_COMMENT_API.CREATE_COMMENT, commentData);
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to create auction comment',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Update auction comment
    updateComment: async (commentId, commentData) => {
        try {
            const response = await axiosClient.put(AUCTION_COMMENT_API.UPDATE_COMMENT(commentId), commentData);
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to update auction comment',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Delete auction comment
    deleteComment: async (commentId) => {
        try {
            const response = await axiosClient.delete(AUCTION_COMMENT_API.DELETE_COMMENT(commentId));
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to delete auction comment',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Get auction comment by ID
    getCommentById: async (commentId) => {
        try {
            const response = await axiosClient.get(AUCTION_COMMENT_API.GET_COMMENT(commentId));
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to fetch auction comment',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },

    // Get comments by user ID
    getCommentsByUserId: async (userId, page = 1, limit = 10) => {
        try {
            const response = await axiosClient.get(AUCTION_COMMENT_API.GET_USER_COMMENTS(userId), {
                params: { page, limit }
            });
            return response.data;
        } catch (err) {
            const statusCode = err?.status;
            const { message, code } = err?.response?.data || {};
            return Promise.reject({
                statusCode: statusCode || 500,
                message: message || 'Failed to fetch user auction comments',
                errorCode: code || 'INTERNAL_SERVER_ERROR',
            });
        }
    },
};
