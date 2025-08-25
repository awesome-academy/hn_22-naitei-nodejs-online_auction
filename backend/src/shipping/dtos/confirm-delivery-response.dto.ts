import { OrderStatus } from '@common/enums/order-status.enum';

export interface ConfirmDeliveryResponseDto {
  message: string;
  shippingInfo: {
    id: string;
    auctionId: string;
    shippingStatus: string;
    actualDelivery: Date | null;
    updatedAt: Date;
  };
  orderInfo: {
    status: OrderStatus;
    completedAt: Date;
  };
  auctionInfo: {
    id: string;
    title: string;
    winningBid: number;
  };
}
