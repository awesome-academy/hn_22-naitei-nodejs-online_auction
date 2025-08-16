import axiosClient from "@/utils/axios.js";

const FOLLOW_API = {
    GET_FOLLOW_COUNT: (sellerId) => `/api/follows/${sellerId}/isFollowing`,
    CHECK_FOLLOW_STATUS: (sellerId) => `/api/follows/${sellerId}/status`,
    FOLLOW_SELLER: (sellerId) => `/api/follows/${sellerId}/follow`,
    UNFOLLOW_SELLER: (sellerId) => `/api/follows/${sellerId}/unfollow`,
};

export const followService = {
    // Get follower count for a seller
    getFollowCount: async (sellerId) => {
        try {
            const response = await axiosClient.get(FOLLOW_API.GET_FOLLOW_COUNT(sellerId));
            return response.data;
        } catch (err) {
            const { message } = err?.response?.data || {};
            throw {
                response: {
                    data: {
                        message: message || 'Failed to get follow count'
                    }
                },
                message: message || 'Failed to get follow count',
                statusCode: err?.response?.status || 500,
            };
        }
    },

    // Check if current user follows a seller
    checkFollowStatus: async (sellerId) => {
        try {
            const response = await axiosClient.get(FOLLOW_API.CHECK_FOLLOW_STATUS(sellerId));
            return response.data;
        } catch (err) {
            const { message } = err?.response?.data || {};
            throw {
                response: {
                    data: {
                        message: message || 'Failed to check follow status'
                    }
                },
                message: message || 'Failed to check follow status',
                statusCode: err?.response?.status || 500,
            };
        }
    },

    // Follow a seller
    followSeller: async (sellerId) => {
        try {
            const response = await axiosClient.post(FOLLOW_API.FOLLOW_SELLER(sellerId));
            return response.data;
        } catch (err) {
            const { message } = err?.response?.data || {};
            throw {
                response: {
                    data: {
                        message: message || 'Failed to follow seller'
                    }
                },
                message: message || 'Failed to follow seller',
                statusCode: err?.response?.status || 500,
            };
        }
    },

    // Unfollow a seller
    unfollowSeller: async (sellerId) => {
        try {
            const response = await axiosClient.post(FOLLOW_API.UNFOLLOW_SELLER(sellerId));
            return response.data;
        } catch (err) {
            const { message } = err?.response?.data || {};
            throw {
                response: {
                    data: {
                        message: message || 'Failed to unfollow seller'
                    }
                },
                message: message || 'Failed to unfollow seller',
                statusCode: err?.response?.status || 500,
            };
        }
    },
};
