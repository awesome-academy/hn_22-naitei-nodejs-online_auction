import { Prisma } from '@prisma/client';
import { OrderStatus } from '@common/enums/order-status.enum';

export type OrderWithRelations = Prisma.OrderGetPayload<{
  include: {
    user: {
      select: {
        userId: true;
        email: true;
        profile: {
          select: {
            fullName: true;
            phoneNumber: true;
          };
        };
      };
    };
    auction: {
      select: {
        auctionId: true;
        title: true;
        startingPrice: true;
        currentPrice: true;
        startTime: true;
        endTime: true;
        sellerId: true;
        seller: {
          select: {
            userId: true;
            email: true;
            profile: {
              select: {
                fullName: true;
                phoneNumber: true;
              };
            };
          };
        };
        auctionProducts: {
          select: {
            product: {
              select: {
                productId: true;
                name: true;
                images: {
                  select: {
                    imageUrl: true;
                    isPrimary: true;
                  };
                };
              };
            };
          };
        };
      };
    };
  };
}>;

export type OrderWhereInput = Prisma.OrderWhereInput;

export type OrderCreateInput = Prisma.OrderCreateInput;

export type OrderUpdateInput = Prisma.OrderUpdateInput;

export type OrderSelectInput = Prisma.OrderSelect;

export type OrderIncludeInput = Prisma.OrderInclude;

// Additional types for business logic
export interface OrderSummary {
  orderId: string;
  status: OrderStatus;
  totalAmount: number;
  createdAt: Date;
  auctionTitle: string;
  productNames: string[];
  buyerEmail: string;
  sellerEmail: string;
}

export interface OrderStatusUpdatePayload {
  orderId: string;
  newStatus: OrderStatus;
  updatedBy: string;
  reason?: string;
}

export interface PaymentProcessingData {
  orderId: string;
  userId: string;
  amount: number;
  paymentMethod: string;
  transactionId?: string;
}
