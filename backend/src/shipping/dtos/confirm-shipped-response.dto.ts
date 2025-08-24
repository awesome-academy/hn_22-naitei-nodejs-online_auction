export interface ConfirmShippedResponseDto {
  message: string;
  shippingInfo: {
    id: string;
    auctionId: string;
    shippingStatus: string;
    trackingNumber?: string;
    shippedAt: Date;
    updatedAt: Date;
  };
  orderInfo: {
    status: string;
    updatedAt: Date;
  };
  auctionInfo: {
    id: string;
    title: string;
    winningBid: number;
  };
}
