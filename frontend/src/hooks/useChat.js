import { useState, useEffect, useCallback, useRef } from 'react';
import { useUser } from '@/contexts/UserContext.jsx';
import { useNotification } from '@/contexts/NotificationContext.jsx';
import { chatApiService } from '@/services/chat.service.js';
import { chatWebSocketService } from '@/services/chat-websocket.service.js';

export const useChat = () => {
  const [rooms, setRooms] = useState([]);
  const [currentRoom, setCurrentRoom] = useState(null);
  const [messages, setMessages] = useState([]);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(false);
  const [typing, setTyping] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);

  // ✅ Cache messages cho từng room
  const messagesCache = useRef(new Map());

  const { user } = useUser();
  const { showToastNotification } = useNotification();
  const typingTimeoutRef = useRef(null);

  const fetchRooms = useCallback(async () => {
    if (!user?.id) return;

    try {
      setLoading(true);
      const response = await chatApiService.getChatRooms();

      if (response.success) {
        setRooms(response.data || []);
      } else {
        setRooms([]);
      }
    } catch (error) {
      showToastNotification('Failed to load chat rooms', 'error');
      setRooms([]);
    } finally {
      setLoading(false);
    }
  }, [user?.id, showToastNotification]);

  const loadMessages = useCallback(async (chatRoomId) => {
    if (!chatRoomId) return;

    try {
      setLoading(true);

      // ✅ Check cache trước
      const cachedMessages = messagesCache.current.get(chatRoomId);
      if (cachedMessages && cachedMessages.length > 0) {
        setMessages(cachedMessages);
        setLoading(false);
        return;
      }

      const response = await chatApiService.getMessages(chatRoomId, {
        limit: 50,
        offset: 0
      });

      if (response.success) {
        const newMessages = response.data || [];
        setMessages(newMessages);
        // ✅ Cache messages
        messagesCache.current.set(chatRoomId, newMessages);
      } else {
        setMessages([]);
      }
    } catch (error) {
      showToastNotification('Failed to load messages', 'error');
      setMessages([]);
    } finally {
      setLoading(false);
    }
  }, [showToastNotification]);

  const markMessagesAsRead = useCallback(async (chatRoomId) => {
    if (!chatRoomId) return;

    try {
      const response = await chatApiService.markMessagesAsRead(chatRoomId);

      if (response.success) {
        setRooms(prev => prev.map(room =>
          room.chatRoomId === chatRoomId
            ? { ...room, unreadCount: 0 }
            : room
        ));
        await fetchUnreadCount();
      }
    } catch (error) {
      // Silent fail
    }
  }, []);

  const fetchUnreadCount = useCallback(async () => {
    if (!user?.id) return;

    try {
      const response = await chatApiService.getUnreadCount();
      if (response.success) {
        const count = response.data?.unreadCount || 0;
        setUnreadCount(count);
      }
    } catch (error) {
      // Silent fail
    }
  }, [user?.id]);

  const selectRoom = useCallback(async (room) => {
    try {
      setCurrentRoom(room);

      // ✅ Load từ cache hoặc API
      await loadMessages(room.chatRoomId);

      if (connected && chatWebSocketService.getConnectionStatus().isConnected) {
        chatWebSocketService.joinRoom(room.chatRoomId);
      }

      // ✅ Mark as read ngay khi vào room
      setTimeout(() => {
        markMessagesAsRead(room.chatRoomId);
      }, 500);

    } catch (error) {
      showToastNotification('Failed to select chat room', 'error');
    }
  }, [connected, loadMessages, showToastNotification, markMessagesAsRead]);

  const sendMessage = useCallback(async (content, type = 'TEXT') => {
    if (!currentRoom?.chatRoomId || !content.trim()) return;

    try {
      if (connected && chatWebSocketService.getConnectionStatus().isConnected) {
        chatWebSocketService.sendMessageWS(currentRoom.chatRoomId, content.trim(), type);
      } else {
        const response = await chatApiService.sendMessage(currentRoom.chatRoomId, {
          content: content.trim(),
          type
        });

        if (response.success) {
          const newMessage = response.data;
          if (newMessage) {
            const updatedMessages = [...messages, {
              ...newMessage,
              tempId: Date.now()
            }];

            setMessages(updatedMessages);
            // ✅ Update cache
            messagesCache.current.set(currentRoom.chatRoomId, updatedMessages);
          }
        }
      }
    } catch (error) {
      showToastNotification('Failed to send message', 'error');
    }
  }, [currentRoom?.chatRoomId, connected, messages, showToastNotification]);

  const createChatRoom = useCallback(async (otherUserId) => {
    try {
      const response = await chatApiService.createOrGetChatRoom({ otherUserId });

      if (response.success) {
        await fetchRooms();

        const roomData = response.data.chatRoom;
        const room = {
          chatRoomId: roomData.chatRoomId,
          otherUser: response.data.otherUser,
          unreadCount: 0,
          lastMessage: null
        };

        await selectRoom(room);
      } else {
        throw new Error(response.message);
      }
    } catch (error) {
      showToastNotification('Failed to create chat room', 'error');
    }
  }, [fetchRooms, selectRoom, showToastNotification]);

  const deleteChatRoom = useCallback(async (chatRoomId) => {
    try {
      setLoading(true);
      const response = await chatApiService.deleteChatRoom(chatRoomId);

      if (response.success) {
        setRooms(prev => prev.filter(room => room.chatRoomId !== chatRoomId));

        // ✅ Clear cache for deleted room
        messagesCache.current.delete(chatRoomId);

        if (currentRoom?.chatRoomId === chatRoomId) {
          setCurrentRoom(null);
          setMessages([]);
        }

        await fetchUnreadCount();

        showToastNotification(
          response.message || 'Chat room deleted successfully',
          'success'
        );

        return true;
      } else {
        throw new Error(response.message);
      }
    } catch (error) {
      showToastNotification(
        error.message || 'Failed to delete chat room',
        'error'
      );
      return false;
    } finally {
      setLoading(false);
    }
  }, [currentRoom, fetchUnreadCount, showToastNotification]);

  useEffect(() => {
    if (!user?.id) return;

    chatWebSocketService.connect();

    const handleConnected = () => {
      setConnected(true);
      fetchRooms();
      fetchUnreadCount();
    };

    const handleDisconnected = () => {
      setConnected(false);
    };

    const handleError = (error) => {
      showToastNotification(error.message || 'Chat connection error', 'error');
    };

    const handleMessage = (message) => {
      // ✅ Check if message is for current room
      const isCurrentRoom = currentRoom &&
        (message.roomId === currentRoom.chatRoomId || message.chatRoomId === currentRoom.chatRoomId);

      if (isCurrentRoom) {
        // ✅ User đang ở trong room này
        if (message.senderId !== user.id) {
          const updatedMessages = [...messages, message];
          setMessages(updatedMessages);
          // ✅ Update cache
          messagesCache.current.set(currentRoom.chatRoomId, updatedMessages);

          // ✅ Tự động mark as read khi nhận message trong current room
          setTimeout(() => {
            markMessagesAsRead(currentRoom.chatRoomId);
          }, 100);
        }
      } else {
        // ✅ Message từ room khác - hiển thị notification
        if (message.notificationText) {
          showToastNotification(
            message.notificationText || `New message from ${message.sender?.email || 'Unknown'}`,
            'info'
          );
        }
      }

      // ✅ Always update rooms and unread count
      fetchRooms();
      fetchUnreadCount();
    };

    const handleMessageSent = (data) => {
      if (data.success && currentRoom && data.data.chatRoomId === currentRoom.chatRoomId) {
        const updatedMessages = [...messages, {
          ...data.data,
          tempId: Date.now()
        }];

        setMessages(updatedMessages);
        // ✅ Update cache
        messagesCache.current.set(currentRoom.chatRoomId, updatedMessages);
      }
      fetchRooms();
    };

    const handleRoomJoined = (data) => {
      if (data.chatRoomId && currentRoom?.chatRoomId === data.chatRoomId) {
        loadMessages(data.chatRoomId);
      }
    };

    const handleUserTyping = (data) => {
      if (currentRoom && data.chatRoomId === currentRoom.chatRoomId && data.userId !== user.id) {
        setTyping(true);

        if (typingTimeoutRef.current) {
          clearTimeout(typingTimeoutRef.current);
        }

        typingTimeoutRef.current = setTimeout(() => {
          setTyping(false);
        }, 3000);
      }
    };

    const handleMessagesRead = (data) => {
      if (currentRoom && data.chatRoomId === currentRoom.chatRoomId) {
        setRooms(prev => prev.map(room =>
          room.chatRoomId === data.chatRoomId
            ? { ...room, unreadCount: 0 }
            : room
        ));
      }
    };

    chatWebSocketService.on('connected', handleConnected);
    chatWebSocketService.on('disconnected', handleDisconnected);
    chatWebSocketService.on('error', handleError);
    chatWebSocketService.on('room_message', handleMessage);
    chatWebSocketService.on('private_message', handleMessage);
    chatWebSocketService.on('new_message', handleMessage);
    chatWebSocketService.on('message_sent', handleMessageSent);
    chatWebSocketService.on('room_joined', handleRoomJoined);
    chatWebSocketService.on('user_typing', handleUserTyping);
    chatWebSocketService.on('messages_read', handleMessagesRead);

    return () => {
      chatWebSocketService.off('connected', handleConnected);
      chatWebSocketService.off('disconnected', handleDisconnected);
      chatWebSocketService.off('error', handleError);
      chatWebSocketService.off('room_message', handleMessage);
      chatWebSocketService.off('private_message', handleMessage);
      chatWebSocketService.off('new_message', handleMessage);
      chatWebSocketService.off('message_sent', handleMessageSent);
      chatWebSocketService.off('room_joined', handleRoomJoined);
      chatWebSocketService.off('user_typing', handleUserTyping);
      chatWebSocketService.off('messages_read', handleMessagesRead);

      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }

      chatWebSocketService.disconnect();
    };
  }, [user?.id, currentRoom, messages, fetchRooms, fetchUnreadCount, showToastNotification, loadMessages, markMessagesAsRead]);

  return {
    rooms,
    currentRoom,
    messages,
    connected,
    loading,
    typing,
    unreadCount,
    selectRoom,
    sendMessage,
    createChatRoom,
    deleteChatRoom,
    fetchRooms,
    loadMessages,
    markMessagesAsRead,
    fetchUnreadCount,
  };
};
