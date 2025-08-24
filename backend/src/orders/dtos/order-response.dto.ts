import { OrderStatus } from '@common/enums/order-status.enum';
import { ShippingStatus } from '@common/enums/shipping-status.enum';

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
    auctionProducts?: Array<{
      product: {
        productId: string;
        name: string;
        images: Array<{
          imageUrl: string;
          isPrimary: boolean;
        }>;
      };
    }>;
  };

  user?: {
    userId: string;
    email: string;
    profile?: {
      fullName: string | null;
      phoneNumber: string | null;
    } | null;
  };

  shipping?: {
    id: string;
    shippingStatus: ShippingStatus;
    price: number | null;
    trackingNumber: string | null;
    shippedAt: Date | null;
    estimatedDelivery: Date | null;
    actualDelivery: Date | null;
    createdAt: Date;
    updatedAt: Date;
  };
}
