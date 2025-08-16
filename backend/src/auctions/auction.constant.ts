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

export const ERROR_PRODUCT_NOT_AVAILABLE = (productId: string) => ({
  statusCode: 404,
  message: `Product not available: ${productId}`,
  errorCode: 'PRODUCT_NOT_AVAILABLE',
});

export const ERROR_AUCTION_NOT_SELLER = {
  statusCode: 403,
  message: 'You are not the seller of this auction.',
  errorCode: 'AUCTION_NOT_SELLER',
};

export const MAX_AUCTIONS_NUMBERS = Number.MAX_SAFE_INTEGER;
