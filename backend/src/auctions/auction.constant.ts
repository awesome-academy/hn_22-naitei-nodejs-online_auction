export const ERROR_INVALID_AUCTION_TIME = {
  statusCode: 400,
  message: 'Start time must be before end time',
  errorCode: 'INVALID_AUCTION_TIME',
};

export const ERROR_PRODUCT_NOT_FOUND = {
  statusCode: 404,
  message: 'One or more products not found',
  errorCode: 'PRODUCT_NOT_FOUND',
};

export const ERROR_PRODUCT_STOCK_INSUFFICIENT = (productId: string) => ({
  statusCode: 400,
  message: `Insufficient stock for product ${productId}`,
  errorCode: 'INSUFFICIENT_PRODUCT_STOCK',
});

export const ERROR_AUCTION_NOT_CLOSED = {
  statusCode: 400,
  message: 'Only closed auctions can be reopened',
  errorCode: 'AUCTION_NOT_CLOSED',
};

export const ERROR_AUCTION_CANNOT_OPEN_AFTER_ENDTIME = {
  statusCode: 400,
  message: 'Auction cannot be reopened after end time',
  errorCode: 'AUCTION_CANNOT_OPEN_AFTER_ENDTIME',
};

export const ERROR_AUCTION_START_TIME_IN_PAST = (minDate: Date) => ({
  statusCode: 400,
  message: `Start time must be in the future (>= ${minDate.toString()})`,
  errorCode: 'INVALID_AUCTION_START_TIME',
});

export const ERROR_AUCTION_NOT_FOUND = {
  statusCode: 404,
  message: 'Auction not found',
  errorCode: 'AUCTION_NOT_FOUND',
};

export const ERROR_AUCTION_NOT_PENDING = {
  statusCode: 400,
  message: 'Only auctions in PENDING status can be evaluated for opening.',
  errorCode: 'AUCTION_NOT_PENDING',
};

export const ERROR_AUCTION_NOT_CANCELLABLE = {
  statusCode: 400,
  message: 'Only auctions in PENDING status can be canceled.',
  errorCode: 'AUCTION_NOT_CANCELLABLE',
};

export const ERROR_AUCTION_NOT_CLOSABLE = {
  statusCode: 400,
  message: 'Only auctions in OPEN or EXTENDED status can be closed.',
  errorCode: 'AUCTION_NOT_CLOSABLE',
};

export const ERROR_PRODUCT_NOT_AVAILABLE = (productName: string) => ({
  statusCode: 404,
  message: `Product not available: ${productName}`,
  errorCode: 'PRODUCT_NOT_AVAILABLE',
});

export const ERROR_AUCTION_NOT_SELLER = {
  statusCode: 403,
  message: 'You are not the seller of this auction.',
  errorCode: 'AUCTION_NOT_SELLER',
};

export const ERROR_INVALID_WEBSOCKET_TOKEN = {
  code: 'WS_INVALID_TOKEN',
  message: 'Invalid websocket token',
};

export const ERROR_USER_NOT_FOUND = {
  code: 'WS_USER_NOT_FOUND',
  message: 'User not found',
};

// Tên các event websocket
export const WS_EVENTS = {
  CONNECTION_SUCCESS: 'connection_success',
  ERROR: 'error',
  JOIN_AUCTION: 'join_auction',
  JOIN_AUCTION_SUCCESS: 'join_auction_success',
  LEAVE_AUCTION: 'leave_auction',
  LEAVE_AUCTION_SUCCESS: 'leave_auction_success',
  USER_JOINED_AUCTION: 'user_joined_auction',
  USER_LEFT_AUCTION: 'user_left_auction',
  PLACE_BID: 'place_bid',
  BID_ACCEPTED: 'bid_accepted',
  BID_HISTORY: 'bid_history',
  AUCTION_ENDED: 'auction_ended',
};

export const MAX_AUCTIONS_NUMBERS = Number.MAX_SAFE_INTEGER;
