import { ShippingStatus } from '@common/enums/shipping-status.enum';
import { OrderStatus } from '@common/enums/order-status.enum';

export interface UserDto {
  userId: string;
  email: string;
  profile?: {
    fullName: string | null;
    phoneNumber?: string | null;
  };
}

export interface ProductDto {
  productId: string;
  name: string;
  images: string[];
}

export interface AuctionDto {
  auctionId: string;
  title: string;
  startingPrice: number;
  winningBid: number;
  startDate: Date;
  endDate: Date;
  sellerId: string;
  seller: UserDto;
  product: ProductDto | null;
}

export interface OrderDto {
  orderId: string;
  totalAmount: number;
  status: OrderStatus;
  paymentDueDate: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ShippingResponseDto {
  id: string;
  auctionId: string;
  sellerId: string;
  buyerId: string;
  shippingStatus: ShippingStatus;
  price: number | null;
  trackingNumber: string | null;
  shippedAt: Date | null;
  estimatedDelivery: Date | null;
  actualDelivery: Date | null;
  createdAt: Date;
  updatedAt: Date;
  seller: UserDto;
  buyer: UserDto;
  auction: AuctionDto;
  order?: OrderDto;
}
