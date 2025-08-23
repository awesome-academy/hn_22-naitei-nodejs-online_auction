import {
  Injectable,
  InternalServerErrorException,
  BadRequestException,
  Logger,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import PrismaService from '@common/services/prisma.service';
import { ShippingStatus } from '@common/enums/shipping-status.enum';
import { OrderStatus } from '@common/enums/order-status.enum';
import { Prisma } from '@prisma/client';
import {
  GetBidderShippingsQueryDto,
  ShippingSortField,
  SortOrder,
} from './dtos/get-bidder-shippings-query.dto';
import { GetSellerShippingsQueryDto } from './dtos/get-seller-shippings-query.dto';
import { ShippingResponseDto } from './dtos/shipping-response.dto';
import { GetBidderShippingsResponseDto } from './dtos/get-bidder-shippings-response.dto';
import { GetSellerShippingsResponseDto } from './dtos/get-seller-shippings-response.dto';
import { ConfirmDeliveryResponseDto } from './dtos/confirm-delivery-response.dto';
import { ConfirmShippedRequestDto } from './dtos/confirm-shipped-request.dto';
import { ConfirmShippedResponseDto } from './dtos/confirm-shipped-response.dto';
import {
  DEFAULT_PAGE,
  DEFAULT_LIMIT,
  SHIPPING_ERRORS,
  SHIPPING_MESSAGES,
  VALIDATION_RULES,
  MAX_LIMIT,
  MIN_PAGE,
} from './shipping.constants';
import { MIN_LIMIT } from 'src/orders/order.constants';

@Injectable()
export class ShippingService {
  private readonly logger = new Logger(ShippingService.name);

  constructor(private readonly prisma: PrismaService) {}

  async getBidderShippings(
    userId: string,
    query: GetBidderShippingsQueryDto,
  ): Promise<GetBidderShippingsResponseDto> {
    try {
      this.validateInputParameters(userId, query);

      const {
        status,
        search,
        page = DEFAULT_PAGE,
        limit = DEFAULT_LIMIT,
        sortBy = ShippingSortField.CREATED_AT,
        sortOrder = SortOrder.DESC,
      } = query;

      const whereClause = this.buildBidderWhereClause(userId, status, search);

      const orderBy = this.buildOrderByClause(sortBy, sortOrder);

      const skip = (page - 1) * limit;
      const take = limit;

      const [totalItems, shippings] = await Promise.all([
        this.prisma.shipping.count({ where: whereClause }),
        this.fetchShippings(whereClause, orderBy, skip, take),
      ]);

      const transformedShippings = this.transformShippings(shippings);

      const pagination = this.calculatePagination(page, limit, totalItems);

      this.logger.log(
        `Successfully retrieved ${transformedShippings.length} shipping records for user ${userId}`,
      );

      return {
        shippings: transformedShippings,
        pagination,
      };
    } catch (error) {
      this.logger.error(
        `Failed to fetch shipping records for user ${userId}`,
        error,
      );

      if (error instanceof BadRequestException) {
        throw error;
      }

      throw new InternalServerErrorException({
        ...SHIPPING_ERRORS.FETCH_FAILED,
        details: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  async getSellerShippings(
    sellerId: string,
    query: GetSellerShippingsQueryDto,
  ): Promise<GetSellerShippingsResponseDto> {
    try {
      this.validateInputParameters(sellerId, query);

      const {
        status,
        search,
        page = DEFAULT_PAGE,
        limit = DEFAULT_LIMIT,
        sortBy = ShippingSortField.CREATED_AT,
        sortOrder = SortOrder.DESC,
      } = query;

      const whereClause = this.buildSellerWhereClause(sellerId, status, search);

      const orderBy = this.buildOrderByClause(sortBy, sortOrder);

      const skip = (page - 1) * limit;
      const take = limit;

      const [totalItems, shippings] = await Promise.all([
        this.prisma.shipping.count({ where: whereClause }),
        this.fetchShippings(whereClause, orderBy, skip, take),
      ]);

      const transformedShippings = this.transformShippings(shippings);

      const pagination = this.calculatePagination(page, limit, totalItems);

      this.logger.log(
        `Successfully retrieved ${transformedShippings.length} shipping records for seller ${sellerId}`,
      );

      return {
        shippings: transformedShippings,
        pagination,
      };
    } catch (error) {
      this.logger.error(
        `Failed to fetch shipping records for seller ${sellerId}`,
        error,
      );

      if (error instanceof BadRequestException) {
        throw error;
      }

      throw new InternalServerErrorException({
        ...SHIPPING_ERRORS.FETCH_FAILED,
        details: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  private validateInputParameters(
    userId: string,
    query: GetBidderShippingsQueryDto | GetSellerShippingsQueryDto,
  ): void {
    if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
      throw new BadRequestException(SHIPPING_ERRORS.INVALID_USER_ID);
    }

    if (
      userId.length < VALIDATION_RULES.USER_ID_MIN_LENGTH ||
      userId.length > VALIDATION_RULES.USER_ID_MAX_LENGTH
    ) {
      throw new BadRequestException(SHIPPING_ERRORS.INVALID_USER_ID);
    }

    if (query.page && query.page < MIN_PAGE) {
      throw new BadRequestException(SHIPPING_ERRORS.INVALID_PAGINATION);
    }

    if (query.limit && (query.limit < MIN_LIMIT || query.limit > MAX_LIMIT)) {
      throw new BadRequestException(SHIPPING_ERRORS.INVALID_PAGINATION);
    }

    if (
      query.search &&
      (query.search.length < VALIDATION_RULES.SEARCH_MIN_LENGTH ||
        query.search.length > VALIDATION_RULES.SEARCH_MAX_LENGTH)
    ) {
      throw new BadRequestException({
        ...SHIPPING_ERRORS.INVALID_PAGINATION,
        message: 'Search term length is invalid',
      });
    }
  }

  private buildBidderWhereClause(
    userId: string,
    status?: ShippingStatus,
    search?: string,
  ): Prisma.ShippingWhereInput {
    const whereClause: Prisma.ShippingWhereInput = {
      buyerId: userId,
    };

    if (status) {
      whereClause.shippingStatus = status;
    }

    if (search && search.trim()) {
      const searchTerm = search.trim();
      whereClause.OR = [
        {
          auction: {
            title: {
              contains: searchTerm,
            },
          },
        },
        {
          auction: {
            auctionProducts: {
              some: {
                product: {
                  name: {
                    contains: searchTerm,
                  },
                },
              },
            },
          },
        },
        {
          seller: {
            email: {
              contains: searchTerm,
            },
          },
        },
        {
          seller: {
            profile: {
              fullName: {
                contains: searchTerm,
              },
            },
          },
        },
        {
          trackingNumber: {
            contains: searchTerm,
          },
        },
      ];
    }

    return whereClause;
  }

  private buildSellerWhereClause(
    sellerId: string,
    status?: ShippingStatus,
    search?: string,
  ): Prisma.ShippingWhereInput {
    const whereClause: Prisma.ShippingWhereInput = {
      sellerId: sellerId,
    };

    if (status) {
      whereClause.shippingStatus = status;
    }

    if (search && search.trim()) {
      const searchTerm = search.trim();
      whereClause.OR = [
        {
          auction: {
            title: {
              contains: searchTerm,
            },
          },
        },
        {
          auction: {
            auctionProducts: {
              some: {
                product: {
                  name: {
                    contains: searchTerm,
                  },
                },
              },
            },
          },
        },
        {
          buyer: {
            email: {
              contains: searchTerm,
            },
          },
        },
        {
          buyer: {
            profile: {
              fullName: {
                contains: searchTerm,
              },
            },
          },
        },
        {
          trackingNumber: {
            contains: searchTerm,
          },
        },
      ];
    }

    return whereClause;
  }

  private buildOrderByClause(
    sortBy: ShippingSortField,
    sortOrder: SortOrder,
  ): Prisma.ShippingOrderByWithRelationInput {
    const orderBy: Prisma.ShippingOrderByWithRelationInput = {};

    switch (sortBy) {
      case ShippingSortField.CREATED_AT:
        orderBy.createdAt = sortOrder;
        break;
      case ShippingSortField.UPDATED_AT:
        orderBy.updatedAt = sortOrder;
        break;
      case ShippingSortField.SHIPPED_AT:
        orderBy.shippedAt = sortOrder;
        break;
      case ShippingSortField.ESTIMATED_DELIVERY:
        orderBy.estimatedDelivery = sortOrder;
        break;
      case ShippingSortField.ACTUAL_DELIVERY:
        orderBy.actualDelivery = sortOrder;
        break;
      default:
        orderBy.createdAt = sortOrder;
        break;
    }

    return orderBy;
  }

  private async fetchShippings(
    whereClause: Prisma.ShippingWhereInput,
    orderBy: Prisma.ShippingOrderByWithRelationInput,
    skip: number,
    take: number,
  ): Promise<any[]> {
    return this.prisma.shipping.findMany({
      where: whereClause,
      include: {
        order: {
          select: {
            orderId: true,
            totalAmount: true,
            status: true,
            paymentDueDate: true,
            createdAt: true,
            updatedAt: true,
          },
        },
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
        buyer: {
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
                      orderBy: {
                        isPrimary: 'desc',
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
  }

  private transformShippings(shippings: any[]): ShippingResponseDto[] {
    return shippings.map((shipping) => ({
      id: shipping.id,
      auctionId: shipping.auctionId,
      sellerId: shipping.sellerId,
      buyerId: shipping.buyerId,
      shippingStatus: shipping.shippingStatus as ShippingStatus,
      price: shipping.price ? Number(shipping.price) : null,
      trackingNumber: shipping.trackingNumber,
      shippedAt: shipping.shippedAt,
      estimatedDelivery: shipping.estimatedDelivery,
      actualDelivery: shipping.actualDelivery,
      createdAt: shipping.createdAt,
      updatedAt: shipping.updatedAt,
      seller: {
        userId: shipping.seller.userId,
        email: shipping.seller.email,
        profile: shipping.seller.profile
          ? {
              fullName: shipping.seller.profile.fullName,
              phoneNumber: shipping.seller.profile.phoneNumber,
            }
          : undefined,
      },
      buyer: {
        userId: shipping.buyer.userId,
        email: shipping.buyer.email,
        profile: shipping.buyer.profile
          ? {
              fullName: shipping.buyer.profile.fullName,
              phoneNumber: shipping.buyer.profile.phoneNumber,
            }
          : undefined,
      },
      auction: {
        auctionId: shipping.auction.auctionId,
        title: shipping.auction.title,
        startingPrice: Number(shipping.auction.startingPrice),
        winningBid: Number(shipping.auction.currentPrice),
        startDate: shipping.auction.startTime,
        endDate: shipping.auction.endTime,
        sellerId: shipping.auction.sellerId,
        seller: {
          userId: shipping.auction.seller.userId,
          email: shipping.auction.seller.email,
          profile: shipping.auction.seller.profile
            ? {
                fullName: shipping.auction.seller.profile.fullName,
                phoneNumber: shipping.auction.seller.profile.phoneNumber,
              }
            : undefined,
        },
        product: shipping.auction.auctionProducts[0]?.product
          ? {
              productId: shipping.auction.auctionProducts[0].product.productId,
              name: shipping.auction.auctionProducts[0].product.name,
              images: shipping.auction.auctionProducts[0].product.images
                .map((img: any) => img.imageUrl)
                .filter(Boolean),
            }
          : null,
      },
      order: shipping.order
        ? {
            orderId: shipping.order.orderId,
            totalAmount: Number(shipping.order.totalAmount),
            status: shipping.order.status as OrderStatus,
            paymentDueDate: shipping.order.paymentDueDate,
            createdAt: shipping.order.createdAt,
            updatedAt: shipping.order.updatedAt,
          }
        : undefined,
    }));
  }

  private calculatePagination(page: number, limit: number, totalItems: number) {
    const totalPages = Math.ceil(totalItems / limit);
    const hasNextPage = page < totalPages;
    const hasPreviousPage = page > 1;

    return {
      currentPage: page,
      totalPages,
      totalItems,
      itemsPerPage: limit,
      hasNextPage,
      hasPreviousPage,
    };
  }

  async confirmDelivery(
    shippingId: string,
    buyerId: string,
  ): Promise<ConfirmDeliveryResponseDto> {
    try {
      const shipping = await this.prisma.shipping.findUnique({
        where: { id: shippingId },
        include: {
          auction: {
            include: {
              orders: true,
            },
          },
        },
      });

      if (!shipping) {
        throw new NotFoundException(SHIPPING_ERRORS.DELIVERY_NOT_FOUND);
      }

      if (shipping.buyerId !== buyerId) {
        throw new ForbiddenException(SHIPPING_ERRORS.DELIVERY_ACCESS_DENIED);
      }

      if (shipping.shippingStatus !== ShippingStatus.IN_TRANSIT) {
        throw new BadRequestException(SHIPPING_ERRORS.DELIVERY_INVALID_STATUS);
      }

      const now = new Date();

      const [updatedShipping] = await this.prisma.$transaction([
        this.prisma.shipping.update({
          where: { id: shippingId },
          data: {
            shippingStatus: ShippingStatus.DELIVERED,
            actualDelivery: now,
            updatedAt: now,
          },
        }),
        ...(shipping.auction.orders.length > 0
          ? [
              this.prisma.order.updateMany({
                where: {
                  auctionId: shipping.auctionId,
                  userId: buyerId,
                },
                data: {
                  status: OrderStatus.COMPLETED,
                  updatedAt: now,
                },
              }),
            ]
          : []),
      ]);

      this.logger.log(
        `Delivery confirmed for shipping ${shippingId} by user ${buyerId}`,
      );

      return {
        message: SHIPPING_MESSAGES.DELIVERY_CONFIRMED,
        shippingInfo: {
          id: updatedShipping.id,
          auctionId: updatedShipping.auctionId,
          shippingStatus: ShippingStatus.DELIVERED,
          actualDelivery: updatedShipping.actualDelivery,
          updatedAt: updatedShipping.updatedAt,
        },
        orderInfo: {
          status: OrderStatus.COMPLETED,
          completedAt: now,
        },
        auctionInfo: {
          id: shipping.auction.auctionId,
          title: shipping.auction.title,
          winningBid: Number(shipping.auction.currentPrice),
        },
      };
    } catch (error) {
      this.logger.error(
        `Failed to confirm delivery for shipping ${shippingId}`,
        error,
      );

      if (
        error instanceof NotFoundException ||
        error instanceof ForbiddenException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }

      throw new InternalServerErrorException(
        SHIPPING_ERRORS.DELIVERY_CONFIRMATION_FAILED,
      );
    }
  }

  async confirmShipped(
    shippingId: string,
    sellerId: string,
    requestData: ConfirmShippedRequestDto,
  ): Promise<ConfirmShippedResponseDto> {
    try {
      const shipping = await this.prisma.shipping.findUnique({
        where: { id: shippingId },
        include: {
          auction: {
            include: {
              orders: true,
            },
          },
          order: true,
        },
      });

      if (!shipping) {
        throw new NotFoundException(SHIPPING_ERRORS.SHIPPED_NOT_FOUND);
      }

      if (shipping.sellerId !== sellerId) {
        throw new ForbiddenException(SHIPPING_ERRORS.SHIPPED_ACCESS_DENIED);
      }

      // Check if the order is in PAID status and shipping is PENDING
      if (
        !shipping.order ||
        shipping.order.status !== OrderStatus.PAID ||
        shipping.shippingStatus !== ShippingStatus.PENDING
      ) {
        throw new BadRequestException(SHIPPING_ERRORS.SHIPPED_INVALID_STATUS);
      }

      const now = new Date();

      const [updatedShipping] = await this.prisma.$transaction([
        this.prisma.shipping.update({
          where: { id: shippingId },
          data: {
            shippingStatus: ShippingStatus.SHIPPED,
            shippedAt: now,
            trackingNumber: requestData.trackingNumber,
            updatedAt: now,
          },
        }),
        this.prisma.order.update({
          where: { orderId: shipping.orderId! },
          data: {
            status: OrderStatus.SHIPPING,
            updatedAt: now,
          },
        }),
      ]);

      this.logger.log(
        `Shipment confirmed for shipping ${shippingId} by seller ${sellerId}`,
      );

      return {
        message: SHIPPING_MESSAGES.SHIPPED_CONFIRMED,
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
          updatedAt: now,
        },
        auctionInfo: {
          id: shipping.auction.auctionId,
          title: shipping.auction.title,
          winningBid: Number(shipping.auction.currentPrice),
        },
      };
    } catch (error) {
      this.logger.error(
        `Failed to confirm shipment for shipping ${shippingId}`,
        error,
      );

      if (
        error instanceof NotFoundException ||
        error instanceof ForbiddenException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }

      throw new InternalServerErrorException(
        SHIPPING_ERRORS.SHIPPED_CONFIRMATION_FAILED,
      );
    }
  }
}
