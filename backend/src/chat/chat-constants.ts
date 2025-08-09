// Chat error constants
export const ERROR_CHAT_ROOM_NOT_FOUND = {
  code: 'CHAT_ROOM_NOT_FOUND',
  message: 'Chat room not found',
};

export const ERROR_CANNOT_JOIN_ROOM = {
  code: 'CANNOT_JOIN_ROOM',
  message: 'You cannot join this room',
};

export const ERROR_NOT_ROOM_MEMBER = {
  code: 'NOT_ROOM_MEMBER',
  message: 'You are not a member of this chat room',
};

export const ERROR_MESSAGE_NOT_FOUND = {
  code: 'MESSAGE_NOT_FOUND',
  message: 'Message not found',
};

export const ERROR_FAILED_TO_SEND_MESSAGE = {
  code: 'FAILED_TO_SEND_MESSAGE',
  message: 'Failed to send message',
};

export const ERROR_FAILED_TO_JOIN_ROOM = {
  code: 'FAILED_TO_JOIN_ROOM',
  message: 'Failed to join chat room',
};

export const ERROR_FAILED_TO_MARK_READ = {
  code: 'FAILED_TO_MARK_READ',
  message: 'Failed to mark messages as read',
};

export const ERROR_INVALID_MESSAGE_TYPE = {
  code: 'INVALID_MESSAGE_TYPE',
  message: 'Invalid message type',
};

export const ERROR_MESSAGE_TOO_LONG = {
  code: 'MESSAGE_TOO_LONG',
  message: 'Message content is too long',
};

export const ERROR_EMPTY_MESSAGE = {
  code: 'EMPTY_MESSAGE',
  message: 'Message content cannot be empty',
};

export const ERROR_FILE_UPLOAD_FAILED = {
  code: 'FILE_UPLOAD_FAILED',
  message: 'Failed to upload file',
};

export const ERROR_INVALID_FILE_TYPE = {
  code: 'INVALID_FILE_TYPE',
  message: 'Invalid file type',
};

export const ERROR_FILE_TOO_LARGE = {
  code: 'FILE_TOO_LARGE',
  message: 'File size is too large',
};

export const ERROR_WEBSOCKET_CONNECTION_FAILED = {
  code: 'WEBSOCKET_CONNECTION_FAILED',
  message: 'WebSocket connection failed',
};

export const ERROR_UNAUTHORIZED_WEBSOCKET = {
  code: 'UNAUTHORIZED_WEBSOCKET',
  message: 'Unauthorized WebSocket connection',
};

export const ERROR_INVALID_WEBSOCKET_TOKEN = {
  code: 'INVALID_WEBSOCKET_TOKEN',
  message: 'Invalid WebSocket token',
};

export const ERROR_CANNOT_CHAT_WITH_SELF = {
  code: 'CANNOT_CHAT_WITH_SELF',
  message: 'Cannot create chat room with yourself',
};

export const ERROR_FAILED_TO_GET_CHAT_ROOMS = {
  code: 'FAILED_TO_GET_CHAT_ROOMS',
  message: 'Failed to get chat rooms',
};

export const ERROR_FAILED_TO_CREATE_CHAT_ROOM = {
  code: 'FAILED_TO_CREATE_CHAT_ROOM',
  message: 'Failed to create/get chat room',
};

export const ERROR_FAILED_TO_GET_MESSAGES = {
  code: 'FAILED_TO_GET_MESSAGES',
  message: 'Failed to get messages',
};

export const ERROR_FAILED_TO_GET_UNREAD_COUNT = {
  code: 'FAILED_TO_GET_UNREAD_COUNT',
  message: 'Failed to get unread count',
};

export const ERROR_FAILED_TO_GET_CHAT_ROOM_DETAILS = {
  code: 'FAILED_TO_GET_CHAT_ROOM_DETAILS',
  message: 'Failed to get chat room details',
};

export const ERROR_NO_ACCESS_TO_CHAT_ROOM = {
  code: 'NO_ACCESS_TO_CHAT_ROOM',
  message: 'You do not have access to this chat room',
};

export const ERROR_FAILED_TO_GET_USER_INFO = {
  code: 'FAILED_TO_GET_USER_INFO',
  message: 'Failed to get user info',
};

export const ERROR_FAILED_TO_GET_OR_CREATE_CHAT_ROOM = {
  code: 'FAILED_TO_GET_OR_CREATE_CHAT_ROOM',
  message: 'Failed to get or create chat room',
};

export const ERROR_FAILED_TO_GET_MESSAGES_WITH_QUERY = {
  code: 'FAILED_TO_GET_MESSAGES_WITH_QUERY',
  message: 'Failed to get messages with query',
};

export const ERROR_FAILED_TO_GET_UNREAD_MESSAGES_COUNT = {
  code: 'FAILED_TO_GET_UNREAD_MESSAGES_COUNT',
  message: 'Failed to get unread messages count',
};

export const ERROR_FAILED_TO_VALIDATE_USER_ROOM_ACCESS = {
  code: 'FAILED_TO_VALIDATE_USER_ROOM_ACCESS',
  message: 'Failed to validate user room access',
};

export const ERROR_FAILED_TO_GET_OTHER_USER_IN_ROOM = {
  code: 'FAILED_TO_GET_OTHER_USER_IN_ROOM',
  message: 'Failed to get other user in room',
};

export const ERROR_FAILED_TO_BROADCAST_MESSAGE = {
  code: 'FAILED_TO_BROADCAST_MESSAGE',
  message: 'Failed to broadcast message',
};

export const ERROR_FAILED_TO_BROADCAST_MESSAGES_READ = {
  code: 'FAILED_TO_BROADCAST_MESSAGES_READ',
  message: 'Failed to broadcast messages read',
};

export const ERROR_UNKNOWN = {
  code: 'UNKNOWN_ERROR',
  message: 'Unknown error occurred',
};

export const ERROR_FAILED_TO_DELETE_CHAT_ROOM = {
  code: 'FAILED_TO_DELETE_CHAT_ROOM',
  message: 'Failed to delete chat room',
};

/////////////////////////////// Chat SUCCESS constants////////////////////////////////
export const SUCCESS_MESSAGE_SENT = {
  code: 'MESSAGE_SENT_SUCCESS',
  message: 'Message sent successfully',
};

export const SUCCESS_ROOM_JOINED = {
  code: 'ROOM_JOINED_SUCCESS',
  message: 'Joined chat room successfully',
};

export const SUCCESS_ROOM_LEFT = {
  code: 'ROOM_LEFT_SUCCESS',
  message: 'Left chat room successfully',
};

export const SUCCESS_MESSAGES_MARKED_READ = {
  code: 'MESSAGES_MARKED_READ_SUCCESS',
  message: 'Messages marked as read successfully',
};

export const SUCCESS_CHAT_ROOM_CREATED = {
  code: 'CHAT_ROOM_CREATED_SUCCESS',
  message: 'Chat room created successfully',
};

export const SUCCESS_FILE_UPLOADED = {
  code: 'FILE_UPLOADED_SUCCESS',
  message: 'File uploaded successfully',
};

export const SUCCESS_CHAT_ROOMS_RETRIEVED = {
  code: 'CHAT_ROOMS_RETRIEVED_SUCCESS',
  message: 'Chat rooms retrieved successfully',
};

export const SUCCESS_CHAT_ROOM_CREATED_OR_RETRIEVED = {
  code: 'CHAT_ROOM_CREATED_OR_RETRIEVED_SUCCESS',
  message: 'Chat room created/retrieved successfully',
};

export const SUCCESS_MESSAGES_RETRIEVED = {
  code: 'MESSAGES_RETRIEVED_SUCCESS',
  message: 'Messages retrieved successfully',
};

export const SUCCESS_UNREAD_COUNT_RETRIEVED = {
  code: 'UNREAD_COUNT_RETRIEVED_SUCCESS',
  message: 'Unread count retrieved successfully',
};

export const SUCCESS_CHAT_ROOM_DETAILS_RETRIEVED = {
  code: 'CHAT_ROOM_DETAILS_RETRIEVED_SUCCESS',
  message: 'Chat room details retrieved successfully',
};

export const SUCCESS_NO_CHAT_ROOMS = {
  code: 'NO_CHAT_ROOMS_FOUND',
  message: 'No chat rooms found',
};

export const SUCCESS_CHAT_ROOM_DELETED = {
  code: 'CHAT_ROOM_DELETED_SUCCESS',
  message: 'Chat room deleted successfully',
};

// Chat validation constants
export const CHAT_VALIDATION = {
  MESSAGE: {
    MAX_LENGTH: 30000,
    MESSAGE: 'Message content must not exceed 30000 characters',
  },
  FILE: {
    MAX_SIZE: 10 * 1024 * 1024, // 10MB
    ALLOWED_TYPES: ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain'],
    MESSAGE: 'File must be an image, PDF, or text file and not exceed 10MB',
  },
  ROOM: {
    MAX_PARTICIPANTS: 2, // For 1-on-1 chat
    MESSAGE: 'Room can only have 2 participants',
  },
};

export const WS_EVENTS = {
  // Client to Server
  JOIN_ROOM: 'join_chat_room',
  LEAVE_ROOM: 'leave_room',
  SEND_MESSAGE: 'send_message',
  TYPING_START: 'typing_start',
  TYPING_STOP: 'typing_stop',
  MARK_READ: 'mark_messages_read',
  GET_ONLINE_USERS: 'get_online_users',
  MORE_MESSAGES: 'get_more_messages',
  MESSAGE_SENT: 'message_sent',
  CONNECTION_SUCCESS: 'connection_success',

  // Server to Client
  ROOM_JOINED: 'chat_room_joined',
  ROOM_LEFT: 'room_left',
  NEW_MESSAGE: 'new_message',
  MESSAGE_NOTIFICATION: 'message_notification',
  USER_TYPING: 'user_typing',
  MESSAGES_READ: 'messages_read',
  USER_JOINED: 'user_joined',
  USER_LEFT: 'user_left',
  USER_STATUS_CHANGED: 'user_status_changed',
  ONLINE_USERS_LIST: 'online_users_list',
  ERROR: 'error',
  GET_MORE_MESSAGES: 'get_more_messages_response',
  ROOM_MESSAGE: 'room_message',
} as const;

export const MESSAGE_STATUS = {
  SENT: 'SENT',
  DELIVERED: 'DELIVERED',
  READ: 'READ',
};

export const MESSAGE_TYPES = {
  TEXT: 'TEXT',
  IMAGE: 'IMAGE',
  FILE: 'FILE',
  SYSTEM: 'SYSTEM',
};

export const OFFSET_DEFAULT = 0;
export const LIMIT_DEFAULT = 50;
