import {
  Injectable,
  ForbiddenException,
  InternalServerErrorException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import PrismaService from '@common/services/prisma.service';
import { Role } from '@common/enums/role.enum';
import { OrderStatus } from '@common/enums/order-status.enum';
import { ShippingStatus } from '@common/enums/shipping-status.enum';
import { AuctionStatus } from '@prisma/client';
import {
  GetOrdersQueryDto,
  OrderSortField,
  SortOrder,
} from './dtos/get-orders-query.dto';
import { OrderResponseDto } from './dtos/order-response.dto';
import { GetOrdersResponseDto } from './dtos/get-orders-response.dto';
import { Prisma } from '@prisma/client';
import {
  DEFAULT_PAGE,
  DEFAULT_LIMIT,
  ERROR_MESSAGES,
  SUCCESS_MESSAGES,
} from './order.constants';
import { ConfirmShippedRequestDto } from '../shipping/dtos/confirm-shipped-request.dto';
import { ConfirmShippedResponseDto } from '../shipping/dtos/confirm-shipped-response.dto';

@Injectable()
export class OrdersService {
  constructor(private readonly prisma: PrismaService) {}

  async createOrderFromAuction(
    auctionId: string,
    winnerId: string,
    finalPrice: number,
  ): Promise<{ orderId: string }> {
    try {
      // Use transaction with retry mechanism to handle race conditions
      const result = await this.prisma.$transaction(
        async (tx) => {
          // Get auction details to validate within transaction
          const auction = await tx.auction.findUnique({
            where: { auctionId },
            include: {
              auctionProducts: {
                include: {
                  product: true,
                },
              },
            },
          });

          if (!auction) {
            throw new NotFoundException('Auction not found');
          }

          if (auction.status !== AuctionStatus.COMPLETED) {
            throw new BadRequestException('Auction must be completed to create order');
          }

          if (auction.winnerId !== winnerId) {
            throw new BadRequestException('Only the auction winner can have an order created');
          }

          // Check if order already exists within transaction
          const existingOrder = await tx.order.findFirst({
            where: {
              auctionId,
              userId: winnerId,
            },
          });

          if (existingOrder) {
            return { orderId: existingOrder.orderId };
          }

          // Calculate payment due date (7 days from now)
          const paymentDueDate = new Date();
          paymentDueDate.setDate(paymentDueDate.getDate() + 7);

          // Create the order
          const order = await tx.order.create({
            data: {
              userId: winnerId,
              auctionId,
              totalAmount: finalPrice,
              status: OrderStatus.PAID,
              paymentDueDate,
            },
          });

          // Create shipping record
          await tx.shipping.create({
            data: {
              orderId: order.orderId,
              auctionId,
              sellerId: auction.sellerId,
              buyerId: winnerId,
              shippingStatus: ShippingStatus.PENDING,
            },
          });

          return { orderId: order.orderId };
        },
        {
          maxWait: 5000, // 5 seconds
          timeout: 10000, // 10 seconds
        }
      );

      return result;
    } catch (error) {
      // Handle Prisma unique constraint violation (P2002)
      if (error instanceof Error && 'code' in error && error.code === 'P2002') {
        // If duplicate order creation due to race condition, try to find existing order
        const existingOrder = await this.prisma.order.findFirst({
          where: {
            auctionId,
            userId: winnerId,
          },
        });
        
        if (existingOrder) {
          return { orderId: existingOrder.orderId };
        }
      }

      if (
        error instanceof NotFoundException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }

      throw new InternalServerErrorException(
        `Failed to create order: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  async getOrders(
    userId: string,
    userRole: Role,
    query: GetOrdersQueryDto,
  ): Promise<GetOrdersResponseDto> {
    const {
      status,
      search,
      page = DEFAULT_PAGE,
      limit = DEFAULT_LIMIT,
      sortBy = OrderSortField.CREATED_AT,
      sortOrder = SortOrder.DESC,
    } = query;

    const whereClause: Prisma.OrderWhereInput = {
      auction: {
        status: AuctionStatus.COMPLETED,
        winnerId: {
          not: null,
        },
      },
    };

    switch (userRole) {
      case Role.BIDDER:
        // Bidder can only see orders where they won the auction
        whereClause.userId = userId;
        break;

      case Role.SELLER:
        // Seller can see orders for auctions they created
        if (whereClause.auction && typeof whereClause.auction === 'object') {
          whereClause.auction.sellerId = userId;
        }
        break;

      case Role.ADMIN:
        // Admin can see all orders
        break;

      default:
        throw new ForbiddenException(ERROR_MESSAGES.INVALID_USER_ROLE);
    }

    if (status) {
      whereClause.status = status;
    }

    if (search) {
      whereClause.OR = [
        {
          auction: {
            status: AuctionStatus.COMPLETED,
            winnerId: {
              not: null,
            },
            title: {
              contains: search,
            },
          },
        },
        {
          auction: {
            status: AuctionStatus.COMPLETED,
            winnerId: {
              not: null,
            },
            auctionProducts: {
              some: {
                product: {
                  name: {
                    contains: search,
                  },
                },
              },
            },
          },
        },
        {
          user: {
            email: {
              contains: search,
            },
          },
        },
        {
          user: {
            profile: {
              fullName: {
                contains: search,
              },
            },
          },
        },
      ];
    }

    const skip = (page - 1) * limit;
    const take = limit;

    const orderBy: Prisma.OrderOrderByWithRelationInput = {};
    switch (sortBy) {
      case OrderSortField.TOTAL_AMOUNT:
        orderBy.totalAmount = sortOrder;
        break;
      case OrderSortField.CREATED_AT:
        orderBy.createdAt = sortOrder;
        break;
      case OrderSortField.UPDATED_AT:
        orderBy.updatedAt = sortOrder;
        break;
      default:
        orderBy.createdAt = sortOrder;
        break;
    }

    try {
      const totalItems = await this.prisma.order.count({
        where: whereClause,
      });

      const orders = await this.prisma.order.findMany({
        where: whereClause,
        include: {
          user: {
            select: {
              userId: true,
              email: true,
              profile: {
                select: {
                  fullName: true,
                  phoneNumber: true,
                },
              },
            },
          },
          auction: {
            select: {
              auctionId: true,
              title: true,
              startingPrice: true,
              currentPrice: true,
              startTime: true,
              endTime: true,
              sellerId: true,
              seller: {
                select: {
                  userId: true,
                  email: true,
                  profile: {
                    select: {
                      fullName: true,
                      phoneNumber: true,
                    },
                  },
                },
              },
              auctionProducts: {
                select: {
                  product: {
                    select: {
                      productId: true,
                      name: true,
                      images: {
                        select: {
                          imageUrl: true,
                          isPrimary: true,
                        },
                      },
                    },
                  },
                },
              },
            },
          },
          shipping: {
            select: {
              id: true,
              shippingStatus: true,
              price: true,
              trackingNumber: true,
              shippedAt: true,
              estimatedDelivery: true,
              actualDelivery: true,
              createdAt: true,
              updatedAt: true,
            },
          },
        },
        orderBy,
        skip,
        take,
      });

      const transformedOrders: OrderResponseDto[] = orders.map((order) => ({
        orderId: order.orderId,
        userId: order.userId,
        auctionId: order.auctionId,
        totalAmount: Number(order.totalAmount),
        status: order.status as OrderStatus,
        paymentDueDate: order.paymentDueDate,
        createdAt: order.createdAt,
        updatedAt: order.updatedAt,
        user: order.user,
        auction: order.auction
          ? {
              auctionId: order.auction.auctionId,
              title: order.auction.title,
              description: '',
              startingPrice: Number(order.auction.startingPrice),
              winningBid: Number(order.auction.currentPrice),
              startDate: order.auction.startTime,
              endDate: order.auction.endTime,
              sellerId: order.auction.sellerId,
              seller: order.auction.seller,
              auctionProducts: order.auction.auctionProducts.map((ap) => ({
                product: {
                  productId: ap.product.productId,
                  name: ap.product.name,
                  images: ap.product.images.map((img) => ({
                    imageUrl: img.imageUrl,
                    isPrimary: img.isPrimary,
                  })),
                },
              })),
            }
          : undefined,
        shipping: order.shipping
          ? {
              id: order.shipping.id,
              shippingStatus: order.shipping.shippingStatus as ShippingStatus,
              price: order.shipping.price ? Number(order.shipping.price) : null,
              trackingNumber: order.shipping.trackingNumber,
              shippedAt: order.shipping.shippedAt,
              estimatedDelivery: order.shipping.estimatedDelivery,
              actualDelivery: order.shipping.actualDelivery,
              createdAt: order.shipping.createdAt,
              updatedAt: order.shipping.updatedAt,
            }
          : undefined,
      }));

      const totalPages = Math.ceil(totalItems / limit);
      const hasNextPage = page < totalPages;
      const hasPreviousPage = page > 1;

      return {
        orders: transformedOrders,
        pagination: {
          currentPage: page,
          totalPages,
          totalItems,
          itemsPerPage: limit,
          hasNextPage,
          hasPreviousPage,
        },
      };
    } catch (error) {
      throw new InternalServerErrorException(
        `${ERROR_MESSAGES.FAILED_TO_FETCH_ORDERS}: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  async confirmOrderShipped(
    orderId: string,
    sellerId: string,
    requestData: ConfirmShippedRequestDto,
  ): Promise<ConfirmShippedResponseDto> {
    try {
      // Find the order and related shipping record
      const order = await this.prisma.order.findUnique({
        where: { orderId },
        include: {
          shipping: true,
          auction: {
            select: {
              auctionId: true,
              title: true,
              currentPrice: true,
              sellerId: true,
            },
          },
        },
      });

      if (!order) {
        throw new NotFoundException(ERROR_MESSAGES.ORDER_NOT_FOUND);
      }

      if (order.auction.sellerId !== sellerId) {
        throw new ForbiddenException(
          ERROR_MESSAGES.UNAUTHORIZED_SHIPMENT_CONFIRMATION,
        );
      }

      if (order.status !== OrderStatus.PAID) {
        throw new BadRequestException(
          ERROR_MESSAGES.INVALID_ORDER_STATUS_FOR_SHIPPING,
        );
      }

      if (!order.shipping) {
        throw new BadRequestException(ERROR_MESSAGES.NO_SHIPPING_RECORD);
      }

      if (order.shipping.shippingStatus !== ShippingStatus.PENDING) {
        throw new BadRequestException(ERROR_MESSAGES.INVALID_SHIPPING_STATUS);
      }

      const now = new Date();

      // Update both order and shipping in a transaction
      const [updatedOrder, updatedShipping] = await this.prisma.$transaction([
        this.prisma.order.update({
          where: { orderId },
          data: {
            status: OrderStatus.SHIPPING,
            updatedAt: now,
          },
        }),
        this.prisma.shipping.update({
          where: { id: order.shipping.id },
          data: {
            shippingStatus: ShippingStatus.SHIPPED,
            shippedAt: now,
            trackingNumber: requestData.trackingNumber,
            updatedAt: now,
          },
        }),
      ]);

      return {
        message: SUCCESS_MESSAGES.SHIPMENT_CONFIRMED,
        shippingInfo: {
          id: updatedShipping.id,
          auctionId: updatedShipping.auctionId,
          shippingStatus: ShippingStatus.SHIPPED,
          trackingNumber: updatedShipping.trackingNumber || undefined,
          shippedAt: updatedShipping.shippedAt!,
          updatedAt: updatedShipping.updatedAt,
        },
        orderInfo: {
          status: OrderStatus.SHIPPING,
          updatedAt: updatedOrder.updatedAt,
        },
        auctionInfo: {
          id: order.auction.auctionId,
          title: order.auction.title,
          winningBid: Number(order.auction.currentPrice),
        },
      };
    } catch (error) {
      if (
        error instanceof NotFoundException ||
        error instanceof ForbiddenException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }

      throw new InternalServerErrorException(
        `${ERROR_MESSAGES.FAILED_TO_CONFIRM_SHIPMENT}: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }
}
