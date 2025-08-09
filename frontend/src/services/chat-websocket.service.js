import { io } from 'socket.io-client';
import { getAccessToken } from "@/utils/token-storage.js";

class ChatWebSocketService {
  constructor() {
    this.socket = null;
    this.isConnected = false;
    this.eventCallbacks = new Map();
    this.baseURL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:3000';
  }

  connect() {
    const token = getAccessToken();
    if (!token) {
      this.emit('error', { message: 'No authentication token' });
      return null;
    }

    if (this.socket && this.socket.connected) {
      this.socket.disconnect();
    }

    this.socket = io(`${this.baseURL}/chat`, {
      auth: { token: token },
      transports: ['websocket'],
      forceNew: true,
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5,
      timeout: 20000,
      autoConnect: true,
    });

    this.setupEventHandlers();
    return this.socket;
  }

  setupEventHandlers() {
    if (!this.socket) return;

    this.socket.removeAllListeners();

    this.socket.on('connect', () => {
      this.isConnected = true;
      this.emit('connected');
    });

    this.socket.on('connection_success', (data) => {
      this.emit('connection_success', data);
    });

    this.socket.on('disconnect', (reason) => {
      this.isConnected = false;
      this.emit('disconnected', reason);
    });

    this.socket.on('connect_error', (error) => {
      this.emit('error', error);
    });

    this.socket.on('error', (error) => {
      this.emit('error', error);
    });

    this.socket.on('chat_room_joined', (data) => {
      this.emit('room_joined', data);
    });

    this.socket.on('room_message', (message) => {
      this.emit('room_message', message);
    });

    this.socket.on('private_message', (message) => {
      this.emit('private_message', message);
    });

    this.socket.on('new_message', (message) => {
      this.emit('new_message', message);
    });

    this.socket.on('message_sent', (data) => {
      this.emit('message_sent', data);
    });

    this.socket.on('messages_read', (data) => {
      this.emit('messages_read', data);
    });

    this.socket.on('user_joined', (data) => {
      this.emit('user_joined', data);
    });

    this.socket.on('user_typing', (data) => {
      this.emit('user_typing', data);
    });

    this.socket.on('user_stopped_typing', (data) => {
      this.emit('user_stopped_typing', data);
    });

    this.socket.on('message_notification', (data) => {
      this.emit('message_notification', data);
    });
  }

  disconnect() {
    if (this.socket && this.socket.connected) {
      this.socket.disconnect();
    }
    this.isConnected = false;
  }

  joinRoom(chatRoomIdOrUserId, isUserId = false, query = { limit: 50, offset: 0 }) {
    if (!this.socket || !this.isConnected) return;

    if (isUserId) {
      this.socket.emit('join_chat_room', {
        otherUserId: chatRoomIdOrUserId,
        query
      });
    } else {
      this.socket.emit('join_chat_room', {
        chatRoomId: chatRoomIdOrUserId,
        query
      });
    }
  }

  joinRoomById(chatRoomId, query = { limit: 50, offset: 0 }) {
    this.joinRoom(chatRoomId, false, query);
  }

  joinRoomByUserId(otherUserId, query = { limit: 50, offset: 0 }) {
    this.joinRoom(otherUserId, true, query);
  }

  sendMessageWS(chatRoomId, content, type = 'TEXT') {
    if (!this.socket || !this.isConnected) return;

    this.socket.emit('send_message', {
      chatRoomId,
      content,
      type
    });
  }

  markAsReadWS(chatRoomId) {
    if (!this.socket || !this.isConnected) return;
    this.socket.emit('mark_read', { chatRoomId });
  }

  getMoreMessages(chatRoomId, query) {
    if (!this.socket || !this.isConnected) return;
    this.socket.emit('get_more_messages', { chatRoomId, query });
  }

  sendTyping(chatRoomId) {
    if (!this.socket || !this.isConnected) return;
    this.socket.emit('typing_start', { chatRoomId });
  }

  stopTyping(chatRoomId) {
    if (!this.socket || !this.isConnected) return;
    this.socket.emit('typing_stop', { chatRoomId });
  }

  on(event, callback) {
    if (!this.eventCallbacks.has(event)) {
      this.eventCallbacks.set(event, []);
    }
    this.eventCallbacks.get(event).push(callback);
  }

  off(event, callback) {
    if (this.eventCallbacks.has(event)) {
      const callbacks = this.eventCallbacks.get(event);
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }

  emit(event, data) {
    if (this.eventCallbacks.has(event)) {
      this.eventCallbacks.get(event).forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          // Silent error handling
        }
      });
    }
  }

  getConnectionStatus() {
    return {
      isConnected: this.isConnected,
      socketId: this.socket?.id || null,
      socketConnected: this.socket?.connected || false,
    };
  }

  debug() {
    return {
      isConnected: this.isConnected,
      socket: this.socket ? {
        id: this.socket.id,
        connected: this.socket.connected,
        url: this.socket.io.uri,
      } : null,
      eventCallbacks: Array.from(this.eventCallbacks.keys()),
      baseURL: this.baseURL,
    };
  }
}

export const chatWebSocketService = new ChatWebSocketService();
export default chatWebSocketService;
