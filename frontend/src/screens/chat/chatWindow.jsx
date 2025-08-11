import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useChat } from '@/hooks/useChat.js';
import ChatRoomList from './chatRoomList.jsx';
import Message from './message.jsx';
import MessageInput from './input.jsx';
import { Container } from '@/components/ui/Design.jsx';

const ChatWindow = () => {
  const {
    rooms,
    messages,
    currentRoom,
    loading,
    connected,
    typing,
    sendMessage,
    selectRoom,
    createChatRoom,
    deleteChatRoom,
  } = useChat();

  const messagesEndRef = useRef(null);
  const messagesContainerRef = useRef(null);
  const isScrollingRef = useRef(false);
  const lastMessageCountRef = useRef(0);

  const [deleteModal, setDeleteModal] = useState({ isOpen: false, room: null });
  const [isDeleting, setIsDeleting] = useState(false);
  const [isInitialLoad, setIsInitialLoad] = useState(true);

  const scrollToBottom = useCallback((behavior = 'auto') => {
    if (isScrollingRef.current) return;

    isScrollingRef.current = true;

    if (behavior === 'auto' || behavior === 'instant') {
      if (messagesContainerRef.current) {
        messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
      }
    } else {
      requestAnimationFrame(() => {
        if (messagesEndRef.current) {
          messagesEndRef.current.scrollIntoView({
            behavior,
            block: 'end',
            inline: 'nearest'
          });
        }
      });
    }

    setTimeout(() => {
      isScrollingRef.current = false;
    }, behavior === 'smooth' ? 100 : 10);
  }, []);

  useEffect(() => {
    const currentMessageCount = messages.length;
    const previousMessageCount = lastMessageCountRef.current;

    if (currentMessageCount > previousMessageCount && currentMessageCount > 0) {
      setTimeout(() => {
        if (messagesContainerRef.current) {
          messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
        }
      }, 0);
    }

    lastMessageCountRef.current = currentMessageCount;
  }, [messages.length]);

  useEffect(() => {
    if (currentRoom && messages.length > 0 && !loading) {
      setTimeout(() => {
        if (messagesContainerRef.current) {
          messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
        }
      }, 0);

      setTimeout(() => {
        if (messagesContainerRef.current) {
          messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
        }
      }, 50);

      setTimeout(() => {
        if (messagesContainerRef.current) {
          messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
        }
      }, 100);

      setTimeout(() => {
        if (messagesContainerRef.current) {
          messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
        }
      }, 200);
    }
  }, [currentRoom?.chatRoomId, messages.length, loading]);

  useEffect(() => {
    if (!loading && currentRoom && messages.length > 0) {
      setTimeout(() => {
        if (messagesContainerRef.current) {
          messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
        }
      }, 0);

      if (isInitialLoad) {
        setIsInitialLoad(false);
      }
    }
  }, [loading, currentRoom?.chatRoomId, isInitialLoad]);

  const startChatwithOtherUser = async () => {
    const otherUserId = prompt('Enter other user ID to start chat:');
    if (otherUserId && otherUserId.trim()) {
      await createChatRoom(otherUserId.trim());
    }
  };

  const handleDeleteRoom = (room) => {
    setDeleteModal({ isOpen: true, room });
  };

  const handleConfirmDelete = async () => {
    if (!deleteModal.room) return;

    setIsDeleting(true);
    try {
      const success = await deleteChatRoom(deleteModal.room.chatRoomId);
      if (success) {
        setDeleteModal({ isOpen: false, room: null });
      }
    } catch (error) {
    } finally {
      setIsDeleting(false);
    }
  };

  const handleModalClick = (e) => {
    if (e.target === e.currentTarget) {
      setDeleteModal({ isOpen: false, room: null });
    }
  };

  const handleSendMessage = useCallback(async (content, type = 'TEXT') => {
    await sendMessage(content, type);

    if (messagesContainerRef.current) {
      messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
    }

    setTimeout(() => {
      if (messagesContainerRef.current) {
        messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
      }
    }, 10);

    setTimeout(() => {
      if (messagesContainerRef.current) {
        messagesContainerRef.current.scrollTop = messagesContainerRef.current.scrollHeight;
      }
    }, 50);
  }, [sendMessage]);

  return (
    <Container className="max-w-6xl mx-auto py-8">
      <div className="bg-white rounded-lg shadow-lg overflow-hidden">
        <div className="bg-gray-50 px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h1 className="text-xl font-semibold text-gray-900">Chat</h1>
            <div className="flex items-center space-x-4">
              <div className={`flex items-center space-x-2 ${connected ? 'text-green-600' : 'text-red-600'}`}>
                <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`}></div>
                <span className="text-sm font-medium">
                  {connected ? 'Connected' : 'Disconnected'}
                </span>
              </div>

              <div className="text-sm text-gray-500">
                Rooms: {rooms.length}
              </div>

              <button
                onClick={startChatwithOtherUser}
                className="px-3 py-1 bg-blue-500 text-white text-sm rounded hover:bg-blue-600 transition-colors"
              >
                Start New Chat
              </button>
            </div>
          </div>
        </div>

        <div className="flex h-[600px]">
          <div className="w-1/3 border-r border-gray-200 overflow-y-auto bg-gray-50">
            <div className="p-4 border-b border-gray-200 bg-white">
              <h2 className="font-medium text-gray-900">Conversations</h2>
            </div>

            <ChatRoomList
              rooms={rooms}
              onRoomSelect={selectRoom}
              onDeleteRoom={handleDeleteRoom}
              currentRoom={currentRoom}
            />
          </div>

          <div className="flex-1 flex flex-col bg-white">
            {currentRoom ? (
              <>
                <div className="p-4 border-b border-gray-200 bg-gray-50">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <div className="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center">
                        {currentRoom.otherUser?.profile?.profileImageUrl ? (
                          <img
                            src={currentRoom.otherUser.profile.profileImageUrl}
                            alt="Avatar"
                            className="w-full h-full rounded-full object-cover"
                          />
                        ) : (
                          <span className="text-green-600 font-medium text-sm">
                            {currentRoom.otherUser?.profile?.fullName?.charAt(0) ||
                              currentRoom.otherUser?.email?.charAt(0) || '?'}
                          </span>
                        )}
                      </div>
                      <div>
                        <h3 className="font-medium text-gray-900">
                          {currentRoom.otherUser?.profile?.fullName ||
                            currentRoom.otherUser?.email || 'Unknown User'}
                        </h3>
                        {typing && (
                          <p className="text-sm text-gray-500">Typing...</p>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center space-x-4">
                      <div className="text-sm text-gray-500">
                        Room: {currentRoom.chatRoomId.substring(0, 8)}...
                      </div>

                      <button
                        onClick={() => handleDeleteRoom(currentRoom)}
                        className="px-2 py-1 bg-red-100 text-red-700 text-xs rounded hover:bg-red-200 transition-colors"
                        title="Delete this chat room"
                      >
                        🗑️ Delete
                      </button>
                    </div>
                  </div>
                </div>

                <div
                  ref={messagesContainerRef}
                  className="flex-1 overflow-y-auto p-4 space-y-2"
                  style={{ scrollBehavior: 'auto' }}
                >
                  {/* ✅ Only show loading on initial load or when no messages */}
                  {loading && (isInitialLoad || messages.length === 0) ? (
                    <div className="flex items-center justify-center h-full">
                      <div className="text-center">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-2"></div>
                        <p className="text-gray-500">Loading messages...</p>
                      </div>
                    </div>
                  ) : messages.length === 0 ? (
                    <div className="text-center text-gray-500 mt-8">
                      <p className="text-lg">No messages yet</p>
                      <p className="text-sm">Start the conversation!</p>
                    </div>
                  ) : (
                    <>
                      {/* ✅ Always show messages even during background loading */}
                      {messages.map((message, index) => (
                        <Message
                          key={`${message.messageId}-${index}`}
                          message={message}
                        />
                      ))}

                      {/* ✅ Show subtle loading indicator at bottom for new messages */}
                      {loading && !isInitialLoad && messages.length > 0 && (
                        <div className="flex justify-center py-2">
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500 opacity-50"></div>
                        </div>
                      )}

                      <div
                        ref={messagesEndRef}
                        className="h-1 w-full"
                        aria-hidden="true"
                      />
                    </>
                  )}
                </div>

                <MessageInput
                  onSendMessage={handleSendMessage}
                  disabled={!connected}
                />
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center text-gray-500">
                <div className="text-center">
                  <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <svg className="w-8 h-8 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M18 10c0 3.866-3.582 7-8 7a8.841 8.841 0 01-4.083-.98L2 17l1.338-3.123C2.493 12.767 2 11.434 2 10c0-3.866 3.582-7 8-7s8 3.134 8 7zM7 9H5v2h2V9zm8 0h-2v2h2V9zM9 9h2v2H9V9z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <p className="text-lg font-medium">Select a conversation</p>
                  <p className="text-sm">Choose a chat room to start messaging</p>
                  <p className="text-xs text-gray-400 mt-2">
                    {rooms.length > 0 ? `${rooms.length} conversation(s) available` : 'No conversations yet'}
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {deleteModal.isOpen && (
        <div
          className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50"
          onClick={handleModalClick}
        >
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-medium text-gray-900">
                  Delete Conversation
                </h3>
                <button
                  onClick={() => setDeleteModal({ isOpen: false, room: null })}
                  className="text-gray-400 hover:text-gray-600"
                  disabled={isDeleting}
                >
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              {deleteModal.room && (
                <div className="mb-4">
                  <div className="flex items-center space-x-3 mb-3">
                    <div className="w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
                      <svg className="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {deleteModal.room.otherUser?.profile?.fullName || deleteModal.room.otherUser?.email || 'Unknown User'}
                      </p>
                      <p className="text-xs text-gray-500">
                        Room ID: {deleteModal.room.chatRoomId.substring(0, 8)}...
                      </p>
                    </div>
                  </div>

                  <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
                    <div className="flex">
                      <svg className="w-5 h-5 text-yellow-400 mt-0.5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                      <div className="text-sm">
                        <p className="text-yellow-800 font-medium">
                          Are you sure you want to delete this conversation?
                        </p>
                        <p className="text-yellow-700 mt-1">
                          This will hide the conversation from your chat list. The other person can still see and send messages.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              <div className="flex justify-end space-x-3 pt-4">
                <button
                  type="button"
                  onClick={() => setDeleteModal({ isOpen: false, room: null })}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 border border-gray-300 rounded-md hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 transition-colors duration-200"
                  disabled={isDeleting}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleConfirmDelete}
                  disabled={isDeleting}
                  className="px-4 py-2 text-sm font-medium text-white bg-red-600 border border-transparent rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
                >
                  {isDeleting ? (
                    <div className="flex items-center">
                      <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Deleting...
                    </div>
                  ) : (
                    'Delete Conversation'
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </Container>
  );
};

export default ChatWindow;
