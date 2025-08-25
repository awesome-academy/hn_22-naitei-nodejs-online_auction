export const MAX_CONTENT_LENGTH = 1000;
export const MIN_CONTENT_LENGTH = 1;

// Pagination constants
export const DEFAULT_PAGE = 1;
export const DEFAULT_LIMIT = 10;

// Error messages
export const AUCTION_COMMENT_ERRORS = {
  AUCTION_NOT_FOUND: 'Auction not found',
  COMMENT_NOT_FOUND: 'Auction comment not found',
  UNAUTHORIZED_ACCESS: 'You are not authorized to perform this action',
  CONTENT_TOO_LONG: `Comment content must not exceed ${MAX_CONTENT_LENGTH} characters`,
  CONTENT_TOO_SHORT: `Comment content must be at least ${MIN_CONTENT_LENGTH} character long`,
} as const;

// Success messages
export const AUCTION_COMMENT_MESSAGES = {
  COMMENTS_RETRIEVED: 'Comments retrieved successfully',
  COMMENT_DELETED: 'Comment deleted successfully',
  USER_COMMENTS_RETRIEVED: 'User comments retrieved successfully',
} as const;
