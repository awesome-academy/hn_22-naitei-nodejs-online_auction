export const WALLET_CONFIG = {
  MIN_DEPOSIT_AMOUNT: 100, // 100 USD
  MAX_DEPOSIT_AMOUNT: 100000, // 100,000 USD
};

export const WALLET_ERRORS = {
  INVALID_DEPOSIT_AMOUNT: {
    statusCode: 400,
    message: `Deposit amount must be from ${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(WALLET_CONFIG.MIN_DEPOSIT_AMOUNT)} to ${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(WALLET_CONFIG.MAX_DEPOSIT_AMOUNT)}`,
    errorCode: 'INVALID_DEPOSIT_AMOUNT',
  },

  AUCTION_NOT_FOUND: {
    statusCode: 404,
    message: 'Auction not found',
    errorCode: 'AUCTION_NOT_FOUND',
  },

  AUCTION_NOT_OPEN: {
    statusCode: 400,
    message: 'Auction is not open',
    errorCode: 'AUCTION_NOT_OPEN',
  },

  CANNOT_BID_OWN_AUCTION: {
    statusCode: 400,
    message: 'Cannot bid on your own auction',
    errorCode: 'CANNOT_BID_OWN_AUCTION',
  },

  INSUFFICIENT_BALANCE: {
    statusCode: 400,
    message: 'Insufficient wallet balance to place bid',
    errorCode: 'INSUFFICIENT_WALLET_BALANCE',
  },

  USER_NOT_FOUND: {
    statusCode: 404,
    message: 'User not found',
    errorCode: 'USER_NOT_FOUND',
  },

  INSUFFICIENT_BALANCE_FOR_ADJUSTMENT: {
    statusCode: 400,
    message: 'Insufficient balance for adjustment',
    errorCode: 'INSUFFICIENT_BALANCE_FOR_ADJUSTMENT',
  },
};

export const TRANSACTION_DESCRIPTIONS = {
  DEPOSIT: (amount: number) => `Deposit ${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount)} to wallet`,

  BID_PAYMENT: (amount: number, auctionTitle: string) =>
    `Bid ${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount)} for auction: ${auctionTitle}`,

  BID_REFUND: (amount: number, auctionTitle: string) =>
    `Refund bid ${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount)} for auction: ${auctionTitle}`,

  ADMIN_ADJUSTMENT: (amount: number) =>
    `Admin ${amount > 0 ? 'added' : 'deducted'} ${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(Math.abs(amount))}`,
};

export const formatBidMinimumError = (minimumBid: string) =>
  `Bid amount must be greater than ${minimumBid}`;

export const PAGE_DEFAULT = 1;

export const LIMIT_DEFAULT = 20;
