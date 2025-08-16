export const DEFAULT_PAGE = 1;
export const DEFAULT_LIMIT = 10;
export const DEFAULT_SORT_BY = 'createdAt';
export const DEFAULT_SORT_ORDER = 'desc';

export const MIN_PAGE = 1;
export const MAX_LIMIT = 100;
export const MIN_LIMIT = 1;

export const VALID_STATUS_TRANSITIONS = {
  PENDING: ['CONFIRMED', 'CANCELLED'],
  CONFIRMED: ['SHIPPED', 'CANCELLED'],
  SHIPPED: ['DELIVERED', 'CANCELLED'],
  DELIVERED: ['COMPLETED'],
  CANCELLED: [],
  COMPLETED: [],
} as const;

export const VALID_SORT_FIELDS = [
  'totalAmount',
  'createdAt',
  'updatedAt',
] as const;

export const ERROR_ORDER_NOT_FOUND = {
  statusCode: 404,
  message: 'Order not found',
  errorCode: 'ORDER_NOT_FOUND',
};

export const ERROR_ORDER_ACCESS_DENIED = {
  statusCode: 403,
  message: 'Access denied to this order',
  errorCode: 'ORDER_ACCESS_DENIED',
};

export const ERROR_ORDER_INVALID_STATUS = {
  statusCode: 400,
  message: 'Invalid order status',
  errorCode: 'ORDER_INVALID_STATUS',
};

export const ERROR_ORDER_CANNOT_UPDATE = {
  statusCode: 400,
  message: 'Order cannot be updated in current status',
  errorCode: 'ORDER_CANNOT_UPDATE',
};

export const ERROR_ORDER_CANNOT_CANCEL = {
  statusCode: 400,
  message: 'Order cannot be cancelled in current status',
  errorCode: 'ORDER_CANNOT_CANCEL',
};

export const ERROR_ORDER_ALREADY_PAID = {
  statusCode: 400,
  message: 'Order has already been paid',
  errorCode: 'ORDER_ALREADY_PAID',
};

export const ERROR_ORDER_PAYMENT_FAILED = {
  statusCode: 400,
  message: 'Payment processing failed',
  errorCode: 'ORDER_PAYMENT_FAILED',
};

export const ERROR_INSUFFICIENT_BALANCE = {
  statusCode: 400,
  message: 'Insufficient wallet balance',
  errorCode: 'INSUFFICIENT_BALANCE',
};

export const ERROR_INVALID_USER_ROLE = {
  statusCode: 403,
  message: 'Invalid user role for this operation',
  errorCode: 'INVALID_USER_ROLE',
};
