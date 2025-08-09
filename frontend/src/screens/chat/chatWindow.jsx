import React, { useEffect, useRef } from 'react';
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
  } = useChat();

  const messagesEndRef = useRef(null);

  // Auto scroll to bottom when new message arrives
  useEffect(() => {
    if (messages.length > 0) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  // Debug current state
  useEffect(() => {
    console.log('🖼️ ChatWindow State:', {
      roomsCount: rooms.length,
      messagesCount: messages.length,
      currentRoom: currentRoom?.chatRoomId,
      connected,
      loading
    });
  }, [rooms, messages, currentRoom, connected, loading]);

  // Start a chat with a specific user (for testing)
  const startTestChat = async () => {
    const otherUserId = prompt('Enter other user ID to start chat:');
    if (otherUserId && otherUserId.trim()) {
      await createChatRoom(otherUserId.trim());
    }
  };

  return (
    <Container className="max-w-6xl mx-auto py-8">
      <div className="bg-white rounded-lg shadow-lg overflow-hidden">
        {/* Header */}
        <div className="bg-gray-50 px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h1 className="text-xl font-semibold text-gray-900">Chat</h1>
            <div className="flex items-center space-x-4">
              {/* Connection status */}
              <div className={`flex items-center space-x-2 ${
                connected ? 'text-green-600' : 'text-red-600'
              }`}>
                <div className={`w-2 h-2 rounded-full ${
                  connected ? 'bg-green-500' : 'bg-red-500'
                }`}></div>
                <span className="text-sm font-medium">
                  {connected ? 'Connected' : 'Disconnected'}
                </span>
              </div>

              {/* Stats */}
              <div className="text-sm text-gray-500">
                Rooms: {rooms.length} | Messages: {messages.length}
              </div>

              {/* Test button */}
              <button
                onClick={startTestChat}
                className="px-3 py-1 bg-blue-500 text-white text-sm rounded hover:bg-blue-600 transition-colors"
              >
                Start Test Chat
              </button>
            </div>
          </div>
        </div>

        <div className="flex h-[600px]">
          {/* Chat Rooms Sidebar */}
          <div className="w-1/3 border-r border-gray-200 overflow-y-auto bg-gray-50">
            <div className="p-4 border-b border-gray-200 bg-white">
              <h2 className="font-medium text-gray-900">Conversations</h2>
              {loading && (
                <p className="text-sm text-gray-500 mt-1">Loading...</p>
              )}
            </div>

            <ChatRoomList
              rooms={rooms}
              onRoomSelect={selectRoom} // ✅ Use selectRoom instead of joinRoom
              currentRoom={currentRoom}
            />
          </div>

          {/* Chat Messages Area */}
          <div className="flex-1 flex flex-col bg-white">
            {currentRoom ? (
              <>
                {/* Chat Header */}
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

                    <div className="text-sm text-gray-500">
                      Room: {currentRoom.chatRoomId.substring(0, 8)}...
                    </div>
                  </div>
                </div>

                {/* Messages */}
                <div className="flex-1 overflow-y-auto p-4 space-y-2">
                  {loading ? (
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
                      {messages.map((message) => (
                        <Message
                          key={message.messageId}
                          message={message}
                        />
                      ))}
                      <div ref={messagesEndRef} />
                    </>
                  )}
                </div>

                {/* Message Input */}
                <MessageInput
                  onSendMessage={sendMessage}
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
    </Container>
  );
};

export default ChatWindow;
