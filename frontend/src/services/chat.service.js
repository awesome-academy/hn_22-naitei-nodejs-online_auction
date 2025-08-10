import axiosClient from "@/utils/axios.js";

const CHAT_API = {
  GET_ROOMS: '/api/chat/rooms',
  CREATE_ROOM: '/api/chat/rooms',
  GET_MESSAGES: (roomId) => `/api/chat/rooms/${roomId}/messages`,
  SEND_MESSAGE: (roomId) => `/api/chat/rooms/${roomId}/messages`,
  MARK_READ: (roomId) => `/api/chat/rooms/${roomId}/mark-read`,
  UNREAD_COUNT: '/api/chat/unread-count',
  ROOM_DETAILS: (roomId) => `/api/chat/rooms/${roomId}`,
  DELETE_ROOM: (roomId) => `/api/chat/rooms/${roomId}`,
};

export const chatService = {
  getChatRooms: async () => {
    try {
      const response = await axiosClient.get(CHAT_API.GET_ROOMS);
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to fetch chat rooms'
          }
        },
        message: message || 'Failed to fetch chat rooms',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  createOrGetChatRoom: async (otherUserId) => {
    try {
      const response = await axiosClient.post(CHAT_API.CREATE_ROOM, {
        otherUserId
      });
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to create/get chat room'
          }
        },
        message: message || 'Failed to create/get chat room',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  getMessages: async (chatRoomId, query = {}) => {
    try {
      const params = new URLSearchParams();
      if (query.limit) params.append('limit', query.limit.toString());
      if (query.offset) params.append('offset', query.offset.toString());

      const url = `${CHAT_API.GET_MESSAGES(chatRoomId)}${params.toString() ? `?${params}` : ''}`;
      const response = await axiosClient.get(url);
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to fetch messages'
          }
        },
        message: message || 'Failed to fetch messages',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  sendMessage: async (chatRoomId, messageData) => {
    try {
      const response = await axiosClient.post(CHAT_API.SEND_MESSAGE(chatRoomId), {
        content: messageData.content,
        type: messageData.type || 'TEXT',
        fileUrl: messageData.fileUrl || null
      });
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to send message'
          }
        },
        message: message || 'Failed to send message',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  markMessagesAsRead: async (chatRoomId) => {
    try {
      const response = await axiosClient.post(CHAT_API.MARK_READ(chatRoomId));
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to mark messages as read'
          }
        },
        message: message || 'Failed to mark messages as read',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  getUnreadCount: async () => {
    try {
      const response = await axiosClient.get(CHAT_API.UNREAD_COUNT);
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to get unread count'
          }
        },
        message: message || 'Failed to get unread count',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  getChatRoomDetails: async (chatRoomId) => {
    try {
      const response = await axiosClient.get(CHAT_API.ROOM_DETAILS(chatRoomId));
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to fetch room details'
          }
        },
        message: message || 'Failed to fetch room details',
        statusCode: err?.response?.status || 500,
      };
    }
  },

  deleteChatRoom: async (chatRoomId) => {
    try {
      const response = await axiosClient.delete(CHAT_API.DELETE_ROOM(chatRoomId));
      return response.data;
    } catch (err) {
      const { message } = err?.response?.data || {};
      throw {
        response: {
          data: {
            message: message || 'Failed to delete chat room'
          }
        },
        message: message || 'Failed to delete chat room',
        statusCode: err?.response?.status || 500,
      };
    }
  }
};

export const chatApiService = {
  getChatRooms: async () => {
    try {
      const result = await chatService.getChatRooms();
      return { success: true, data: result.data || result };
    } catch (error) {
      return { success: false, message: error.message, data: null };
    }
  },

  getMessages: async (chatRoomId, query) => {
    try {
      const result = await chatService.getMessages(chatRoomId, query);
      return { success: true, data: result.data || result };
    } catch (error) {
      return { success: false, message: error.message, data: null };
    }
  },

  sendMessage: async (chatRoomId, messageData) => {
    try {
      const result = await chatService.sendMessage(chatRoomId, messageData);
      return { success: true, data: result.data || result };
    } catch (error) {
      return { success: false, message: error.message, data: null };
    }
  },

  createOrGetChatRoom: async (data) => {
    try {
      const otherUserId = data.otherUserId || data;
      const result = await chatService.createOrGetChatRoom(otherUserId);
      return { success: true, data: result.data || result };
    } catch (error) {
      return { success: false, message: error.message, data: null };
    }
  },

  markMessagesAsRead: async (chatRoomId) => {
    try {
      const result = await chatService.markMessagesAsRead(chatRoomId);
      return { success: true, data: result.data || result };
    } catch (error) {
      return { success: false, message: error.message, data: null };
    }
  },

  getUnreadCount: async () => {
    try {
      const result = await chatService.getUnreadCount();
      return { success: true, data: result.data || result };
    } catch (error) {
      return { success: false, message: error.message, data: null };
    }
  },

  getChatRoomDetails: async (chatRoomId) => {
    try {
      const result = await chatService.getChatRoomDetails(chatRoomId);
      return { success: true, data: result.data || result };
    } catch (error) {
      return { success: false, message: error.message, data: null };
    }
  },

  deleteChatRoom: async (chatRoomId) => {
    try {
      const result = await chatService.deleteChatRoom(chatRoomId);
      return { success: true, data: result.data || result, message: result.message || 'Chat room deleted successfully' };
    } catch (error) {
      return { success: false, message: error.message, data: null };
    }
  }
};
