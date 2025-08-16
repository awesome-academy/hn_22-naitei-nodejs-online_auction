import { OrderStatus } from '@common/enums/order-status.enum';

export interface OrderResponseDto {
  orderId: string;
  userId: string;
  auctionId: string;
  totalAmount: number;
  status: OrderStatus;
  paymentDueDate: Date | null;
  createdAt: Date;
  updatedAt: Date;

  auction?: {
    auctionId: string;
    title: string;
    description: string;
    startingPrice: number;
    winningBid: number | null;
    startDate: Date;
    endDate: Date;
    sellerId: string;
    seller?: {
      userId: string;
      email: string;
      profile?: {
        fullName: string | null;
        phoneNumber: string | null;
      } | null;
    };
    product?: {
      productId: string;
      name: string;
      images: string[];
    } | null;
  };

  user?: {
    userId: string;
    email: string;
    profile?: {
      fullName: string | null;
      phoneNumber: string | null;
    } | null;
  };
}
