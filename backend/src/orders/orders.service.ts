import {
  Injectable,
  ForbiddenException,
  InternalServerErrorException,
} from '@nestjs/common';
import PrismaService from '@common/services/prisma.service';
import { Role } from '@common/enums/role.enum';
import { OrderStatus } from '@common/enums/order-status.enum';
import {
  GetOrdersQueryDto,
  OrderSortField,
  SortOrder,
} from './dtos/get-orders-query.dto';
import { OrderResponseDto } from './dtos/order-response.dto';
import { GetOrdersResponseDto } from './dtos/get-orders-response.dto';
import { Prisma } from '@prisma/client';
import { DEFAULT_PAGE, DEFAULT_LIMIT } from './order.constants';

@Injectable()
export class OrdersService {
  constructor(private readonly prisma: PrismaService) {}

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

    const whereClause: Prisma.OrderWhereInput = {};

    switch (userRole) {
      case Role.BIDDER:
        // Bidder can only see orders where they won the auction
        whereClause.userId = userId;
        break;

      case Role.SELLER:
        // Seller can see orders for auctions they created
        whereClause.auction = {
          sellerId: userId,
        };
        break;

      case Role.ADMIN:
        // Admin can see all orders
        break;

      default:
        throw new ForbiddenException('Invalid user role');
    }

    if (status) {
      whereClause.status = status;
    }

    if (search) {
      whereClause.OR = [
        {
          auction: {
            title: {
              contains: search,
            },
          },
        },
        {
          auction: {
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
              product: order.auction.auctionProducts[0]?.product
                ? {
                    productId:
                      order.auction.auctionProducts[0].product.productId,
                    name: order.auction.auctionProducts[0].product.name,
                    images: order.auction.auctionProducts[0].product.images.map(
                      (img) => img.imageUrl,
                    ),
                  }
                : null,
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
        `Failed to fetch orders: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }
}
