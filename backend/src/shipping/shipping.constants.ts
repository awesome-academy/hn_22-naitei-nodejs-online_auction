export const DEFAULT_PAGE = 1;
export const DEFAULT_LIMIT = 10;
export const DEFAULT_SORT_BY = 'createdAt';
export const DEFAULT_SORT_ORDER = 'desc';

export const MIN_PAGE = 1;
export const MAX_LIMIT = 100;
export const MIN_LIMIT = 1;

export const VALID_SORT_FIELDS = [
  'createdAt',
  'updatedAt',
  'shippedAt',
  'estimatedDelivery',
  'actualDelivery',
] as const;

export const DATABASE_SORT_MAPPING = {
  createdAt: 'createdAt',
  updatedAt: 'updatedAt',
  shippedAt: 'shippedAt',
  estimatedDelivery: 'estimatedDelivery',
  actualDelivery: 'actualDelivery',
} as const;

export const SEARCH_FIELDS = {
  AUCTION_TITLE: 'auction.title',
  PRODUCT_NAME: 'auction.auctionProducts.product.name',
  SELLER_EMAIL: 'seller.email',
  SELLER_NAME: 'seller.profile.fullName',
  TRACKING_NUMBER: 'trackingNumber',
} as const;

export const SHIPPING_ERRORS = {
  NOT_FOUND: {
    statusCode: 404,
    message: 'Shipping record not found',
    errorCode: 'SHIPPING_NOT_FOUND',
  },
  ACCESS_DENIED: {
    statusCode: 403,
    message: 'Access denied to this shipping record',
    errorCode: 'SHIPPING_ACCESS_DENIED',
  },
  INVALID_STATUS: {
    statusCode: 400,
    message: 'Invalid shipping status',
    errorCode: 'SHIPPING_INVALID_STATUS',
  },
  FETCH_FAILED: {
    statusCode: 500,
    message: 'Failed to fetch shipping records',
    errorCode: 'SHIPPING_FETCH_FAILED',
  },
  INVALID_USER_ID: {
    statusCode: 400,
    message: 'Invalid user ID provided',
    errorCode: 'SHIPPING_INVALID_USER_ID',
  },
  INVALID_PAGINATION: {
    statusCode: 400,
    message: 'Invalid pagination parameters',
    errorCode: 'SHIPPING_INVALID_PAGINATION',
  },
  INVALID_SORT_FIELD: {
    statusCode: 400,
    message: 'Invalid sort field provided',
    errorCode: 'SHIPPING_INVALID_SORT_FIELD',
  },
  DELIVERY_NOT_FOUND: {
    statusCode: 404,
    message: 'Shipping record not found',
    errorCode: 'DELIVERY_NOT_FOUND',
  },
  DELIVERY_ACCESS_DENIED: {
    statusCode: 403,
    message: 'You are not authorized to confirm this delivery',
    errorCode: 'DELIVERY_ACCESS_DENIED',
  },
  DELIVERY_INVALID_STATUS: {
    statusCode: 400,
    message: 'Can only confirm delivery for shipments in transit',
    errorCode: 'DELIVERY_INVALID_STATUS',
  },
  DELIVERY_CONFIRMATION_FAILED: {
    statusCode: 500,
    message: 'Failed to confirm delivery. Please try again later.',
    errorCode: 'DELIVERY_CONFIRMATION_FAILED',
  },
} as const;

export const SHIPPING_MESSAGES = {
  FETCH_SUCCESS: 'Shipping records retrieved successfully',
  NO_RECORDS_FOUND: 'No shipping records found for the given criteria',
  DELIVERY_CONFIRMED: 'Delivery confirmed successfully',
} as const;

export const VALIDATION_RULES = {
  USER_ID_MIN_LENGTH: 1,
  USER_ID_MAX_LENGTH: 36,
  SEARCH_MIN_LENGTH: 1,
  SEARCH_MAX_LENGTH: 255,
  TRACKING_NUMBER_MIN_LENGTH: 1,
  TRACKING_NUMBER_MAX_LENGTH: 100,
} as const;
