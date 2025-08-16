import { CreateAuctionDto } from './dtos/create-auction.body.dto';
import PrismaService from '@common/services/prisma.service';
import {
  BadRequestException,
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import {
  ERROR_AUCTION_NOT_CANCELLABLE,
  ERROR_AUCTION_NOT_CLOSABLE,
  ERROR_AUCTION_NOT_FOUND,
  ERROR_AUCTION_NOT_PENDING,
  ERROR_AUCTION_NOT_SELLER,
  ERROR_AUCTION_START_TIME_IN_PAST,
  ERROR_INVALID_AUCTION_TIME,
  ERROR_PRODUCT_NOT_AVAILABLE,
  ERROR_PRODUCT_NOT_FOUND,
  ERROR_PRODUCT_STOCK_INSUFFICIENT,
} from './auction.constant';
import { AuctionStatus, Prisma } from '@prisma/client';
import { CreateAuctionResponseDto } from './dtos/create-auction.response.dto';
import { SearchAuctionQueryDto } from './dtos/search-auction.query.dto';
import {
  AuctionItemDto,
  SearchAuctionResponseDto,
} from './dtos/search-auction.response.dto';
import {
  GetAuctionDetailResponseDto,
  AuctionProductDetailDto,
} from './dtos/get-auction-detail.response.dto';
import { AddToWatchlistDto } from './dtos/add-to-watchlist.body.dto';
import { ERROR_AUTION_ALREADY_IN_WATCHLIST, ERROR_AUTION_CANT_BE_ADDED_TO_WATCHLIST, ERROR_AUTION_CANT_BE_EDITED, ERROR_AUTION_CANT_BE_REOPENED, ERROR_AUTION_NOT_FOUND } from '@common/constants/error.constant';
import { AddToWatchlistResponseDto } from './dtos/add-to-watchlist.response.dto';
import { RemoveFromWatchlistDto, RemoveFromWatchlistResponseDto } from './dtos/remove-from-watchlist.dto';
import { UpdateAuctionDto } from './dtos/update-auction.body.dto';
import { CancelAuctionDto } from './dtos/cancel-auction.body.dto';
import { ReopenAuctionBodyDto, ReopenAuctionResponseDto } from './dtos/reopen-auction.dto';
import { EditAuctionBodyDto } from './dtos/edit-auction.body.dto';
import { EditAuctionResponseDto } from './dtos/edit-auction.response.dto';

@Injectable()
export class AuctionService {
  constructor(private readonly prisma: PrismaService) { }

  async createAuction(
    user: any,
    dto: CreateAuctionDto,
  ): Promise<CreateAuctionResponseDto> {
    const {
      title,
      startTime,
      endTime,
      startingPrice,
      minimumBidIncrement,
      products,
    } = dto;

    const now = new Date();
    if (new Date(startTime) < now) {
      const { statusCode, message, errorCode } =
        ERROR_AUCTION_START_TIME_IN_PAST(now);
      throw new BadRequestException({ statusCode, message, errorCode });
    }

    if (new Date(startTime) >= new Date(endTime)) {
      throw new BadRequestException(ERROR_INVALID_AUCTION_TIME);
    }

    const productIds = products.map((p) => p.productId);

    const result = await this.prisma.$transaction(async (tx) => {
      const foundProducts = await tx.product.findMany({
        where: { productId: { in: productIds } },
      });

      if (foundProducts.length !== productIds.length)
        throw new NotFoundException(ERROR_PRODUCT_NOT_FOUND);

      const productMap = new Map(
        foundProducts.map((product) => [product.productId, product]),
      );

      for (const { productId, quantity } of products) {
        const product = productMap.get(productId);
        if (!product) continue;

        if (product.status !== 'ACTIVE') {
          const { statusCode, message, errorCode } =
            ERROR_PRODUCT_NOT_AVAILABLE(product.name);
          throw new BadRequestException({ statusCode, message, errorCode });
        }

        if (product.stockQuantity < quantity) {
          const { statusCode, message, errorCode } =
            ERROR_PRODUCT_STOCK_INSUFFICIENT(productId);
          throw new BadRequestException({ statusCode, message, errorCode });
        }

        await tx.product.update({
          where: { productId },
          data: {
            stockQuantity: { decrement: quantity },
          },
        });
      }

      const auction = await tx.auction.create({
        data: {
          title,
          startTime: new Date(startTime),
          endTime: new Date(endTime),
          startingPrice,
          currentPrice: startingPrice,
          minimumBidIncrement,
          lastBidTime: new Date(startTime),
          status: AuctionStatus.PENDING,
          sellerId: user.id,
        },
      });

      await tx.auctionProduct.createMany({
        data: products.map(({ productId, quantity }) => ({
          auctionId: auction.auctionId,
          productId,
          quantity,
        })),
      });

      return auction;
    });

    return {
      auctionId: result.auctionId,
      title: result.title,
      startTime: result.startTime,
      endTime: result.endTime,
      startingPrice: result.startingPrice.toString(),
      minimumBidIncrement: result.minimumBidIncrement.toString(),
      status: result.status,
      products: products.map((product) => ({
        productId: product.productId,
        quantity: product.quantity,
      })),
    };
  }

  async searchAuctions(
    query: SearchAuctionQueryDto,
  ): Promise<SearchAuctionResponseDto> {
    const where: Prisma.AuctionWhereInput = {
      ...(query.sellerId && {
        sellerId: query.sellerId,
      }),
      ...(query.title && {
        title: { contains: query.title },
      }),
      ...(query.categoryType && {
        auctionProducts: {
          some: {
            product: {
              productCategories: {
                some: {
                  category: { name: { in: query.categoryType } },
                },
              },
            },
          },
        },
      }),
      ...(query.status && { status: query.status }),
      ...(query.minPrice && { currentPrice: { gte: query.minPrice } }),
      ...(query.maxPrice && { currentPrice: { lte: query.maxPrice } }),
      ...(query.startTime && { startTime: { gte: new Date(query.startTime) } }),
      ...(query.endTime && { endTime: { lte: new Date(query.endTime) } }),
    };

    const [total, rawAuctions] = await this.prisma.$transaction([
      this.prisma.auction.count({ where }),
      this.prisma.auction.findMany({
        where,
        skip: query.page * query.size,
        take: query.size,
        orderBy: { [query.sortField]: query.sortDirection },
        select: {
          auctionId: true,
          title: true,
          startTime: true,
          endTime: true,
          startingPrice: true,
          currentPrice: true,
          minimumBidIncrement: true,
          status: true,
        },
      }),
    ]);

    const auctions: AuctionItemDto[] = rawAuctions.map((auction) => ({
      auctionId: auction.auctionId,
      title: auction.title,
      startTime: auction.startTime,
      endTime: auction.endTime,
      startingPrice: auction.startingPrice.toString(),
      currentPrice: auction.currentPrice.toString(),
      minimumBidIncrement: auction.minimumBidIncrement.toString(),
      status: auction.status,
    }));

    return { total, page: query.page, size: query.size, data: auctions };
  }

  async getAuctionById(
    auctionId: string,
  ): Promise<GetAuctionDetailResponseDto> {
    const auction = await this.prisma.auction.findUnique({
      where: { auctionId },
      include: {
        seller: {
          select: {
            userId: true,
            profile: { select: { fullName: true } },
          },
        },
        winner: {
          select: {
            userId: true,
            profile: { select: { fullName: true } },
          },
        },
        auctionProducts: {
          include: {
            product: {
              select: {
                productId: true,
                name: true,
                description: true,
                images: { select: { imageUrl: true, imageId: true } },
                productCategories: {
                  select: {
                    category: { select: { name: true, categoryId: true } },
                  },
                },
              },
            },
          },
        },
        bids: {
          select: {
            bidId: true,
            bidAmount: true,
            status: true,
            createdAt: true,
            user: {
              select: {
                userId: true,
                profile: { select: { fullName: true } },
              },
            },
          },
          orderBy: { createdAt: 'desc' },
        },
      },
    });

    if (!auction) {
      throw new NotFoundException(ERROR_AUCTION_NOT_FOUND);
    }

    return {
      auctionId: auction.auctionId,
      title: auction.title,
      startTime: auction.startTime,
      endTime: auction.endTime,
      startingPrice: auction.startingPrice.toString(),
      currentPrice: auction.currentPrice.toString(),
      minimumBidIncrement: auction.minimumBidIncrement.toString(),
      status: auction.status,
      sellerId: auction.seller.userId,
      sellerName: auction.seller.profile?.fullName ?? '',
      lastBidTime: auction.bids?.[0]?.createdAt ?? null,
      winnerId: auction.winner?.userId ?? undefined,
      winnerName: auction.winner?.profile?.fullName ?? undefined,
      createdAt: auction.createdAt,
      bids: auction.bids.map((bid) => ({
        bidId: bid.bidId,
        bidAmount: bid.bidAmount.toString(),
        status: bid.status,
        createdAt: bid.createdAt,
        bidderId: bid.user.userId,
        bidderName: bid.user.profile?.fullName ?? '',
      })),
      products: auction.auctionProducts.map(
        (ap): AuctionProductDetailDto => ({
          productId: ap.product.productId,
          name: ap.product.name,
          description: ap.product.description || '',
          quantity: ap.quantity,
          categories: ap.product.productCategories.map(
            (pc) => pc.category.name,
          ),
          images: ap.product.images.map((img) => img.imageUrl),
        }),
      ),
    };
  }
  async confirmAuction(auctionId: string): Promise<void> {
    const auction = await this.prisma.auction.findUnique({
      where: { auctionId },
    });

    if (!auction) {
      throw new NotFoundException(ERROR_AUCTION_NOT_FOUND);
    }

    if (auction.status !== AuctionStatus.PENDING) {
      throw new BadRequestException(ERROR_AUCTION_NOT_PENDING);
    }

    const now = new Date();
    const newStatus =
      now < auction.startTime ? AuctionStatus.READY : AuctionStatus.OPEN;

    await this.prisma.auction.update({
      where: { auctionId },
      data: {
        status: newStatus,
        lastBidTime: now,
      },
    });
  }

  async cancelAuction(cancelAuctionDto: CancelAuctionDto): Promise<String> {
    const auction = await this.prisma.auction.findUnique({
      where: { auctionId: cancelAuctionDto.auctionId },
    });

    if (!auction) {
      throw new NotFoundException(ERROR_AUCTION_NOT_FOUND);
    }

    if (
      auction.status !== AuctionStatus.PENDING
    ) {
      throw new BadRequestException(ERROR_AUCTION_NOT_CANCELLABLE);
    }

    await this.prisma.auction.update({
      where: { auctionId: cancelAuctionDto.auctionId },
      data: {
        cancelReason: cancelAuctionDto.reason,
        status: AuctionStatus.CANCELED,
      },
    });
    return 'Auction canceled successfully';
  }

  async closeAuction(auctionId: string): Promise<void> {
    const auction = await this.prisma.auction.findUnique({
      where: { auctionId },
    });

    if (!auction) {
      throw new NotFoundException(ERROR_AUCTION_NOT_FOUND);
    }

    if (
      auction.status !== AuctionStatus.OPEN &&
      auction.status !== AuctionStatus.EXTENDED
    ) {
      throw new BadRequestException(ERROR_AUCTION_NOT_CLOSABLE);
    }

    await this.prisma.auction.update({
      where: { auctionId },
      data: {
        status: AuctionStatus.CLOSED,
      },
    });
  }

  async updateAuction(
    user: any,
    auctionId: string,
    dto: UpdateAuctionDto,
  ): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      const auction = await tx.auction.findUnique({
        where: { auctionId },
        include: { auctionProducts: true },
      });

      if (!auction) {
        throw new NotFoundException(ERROR_AUCTION_NOT_FOUND);
      }

      if (auction.sellerId !== user.id) {
        throw new ForbiddenException(ERROR_AUCTION_NOT_SELLER);
      }

      if (auction.status !== AuctionStatus.PENDING) {
        throw new BadRequestException(ERROR_AUCTION_NOT_PENDING);
      }

      const oldProductsMap = new Map(
        auction.auctionProducts.map((ap) => [ap.productId, ap.quantity]),
      );

      const incomingProductIds = dto.products?.map((p) => p.productId) || [];

      const products = await tx.product.findMany({
        where: { productId: { in: incomingProductIds } },
      });

      const productMap = new Map(products.map((p) => [p.productId, p]));

      for (const oldProduct of auction.auctionProducts) {
        if (!incomingProductIds.includes(oldProduct.productId)) {
          await tx.product.update({
            where: { productId: oldProduct.productId },
            data: { stockQuantity: { increment: oldProduct.quantity } },
          });

          await tx.auctionProduct.delete({
            where: {
              auctionId_productId: {
                auctionId,
                productId: oldProduct.productId,
              },
            },
          });
        }
      }

      for (const { productId, quantity } of dto.products || []) {
        const product = productMap.get(productId);
        if (!product) {
          throw new NotFoundException(ERROR_PRODUCT_NOT_FOUND);
        }

        const oldQty = oldProductsMap.get(productId) ?? 0;
        const diff = quantity - oldQty;

        if (diff > 0) {
          if (product.stockQuantity < diff) {
            throw new BadRequestException(
              ERROR_PRODUCT_STOCK_INSUFFICIENT(productId),
            );
          }
          await tx.product.update({
            where: { productId },
            data: { stockQuantity: { decrement: diff } },
          });
        } else if (diff < 0) {
          await tx.product.update({
            where: { productId },
            data: { stockQuantity: { increment: Math.abs(diff) } },
          });
        }

        if (oldQty == 0) {
          await tx.auctionProduct.create({
            data: {
              auctionId,
              productId,
              quantity,
            },
          });
        } else {
          await tx.auctionProduct.update({
            where: { auctionId_productId: { auctionId, productId } },
            data: { quantity },
          });
        }
      }

      await tx.auction.update({
        where: { auctionId },
        data: {
          title: dto.title ?? auction.title,
          endTime: dto.endTime ? new Date(dto.endTime) : auction.endTime,
        },
      });
    });
  }

  async addToWatchlist(currUser: any, addToWatchlistDto: AddToWatchlistDto): Promise<AddToWatchlistResponseDto> {
    const auctionId = addToWatchlistDto.auctionId;
    const auction = await this.prisma.auction.findUnique({
      where: { auctionId },
    });
    if (!auction) {
      throw new NotFoundException(ERROR_AUTION_NOT_FOUND);
    }

    if (auction.status !== AuctionStatus.OPEN && auction.status !== AuctionStatus.READY) {
      throw new BadRequestException(ERROR_AUTION_CANT_BE_ADDED_TO_WATCHLIST);
    }

    const userId = currUser.id;
    const existingWatchlist = await this.prisma.watchlist.findFirst({
      where: {
        userId,
        auctionId,
      },
    });

    if (existingWatchlist) {
      throw new BadRequestException(ERROR_AUTION_ALREADY_IN_WATCHLIST);
    }

    const watchlistItem = await this.prisma.watchlist.create({
      data: {
        userId,
        auctionId,
      },
      select: {
        watchlistId: true,
        auction: {
          select: {
            auctionId: true,
            title: true,
            startTime: true,
            endTime: true,
            startingPrice: true,
            currentPrice: true,
            minimumBidIncrement: true,
            status: true,
            auctionProducts: {
              select: {
                product: {
                  select: {
                    productId: true,
                    name: true,
                    stockQuantity: true,
                    status: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    return {
      auctionId: watchlistItem.auction.auctionId,
      title: watchlistItem.auction.title,
      startTime: watchlistItem.auction.startTime,
      endTime: watchlistItem.auction.endTime,
      startingPrice: watchlistItem.auction.startingPrice,
      minimumBidIncrement: watchlistItem.auction.minimumBidIncrement,
      status: watchlistItem.auction.status,
      products: watchlistItem.auction.auctionProducts.map(ap => ap.product),
    };
  }

  async removeFromWatchlist(currUser: any, removeFromWatchlistDto: RemoveFromWatchlistDto): Promise<RemoveFromWatchlistResponseDto> {
    const auctionId = removeFromWatchlistDto.auctionId;
    const result = await this.prisma.watchlist.deleteMany({
      where: {
        userId: currUser.id,
        auctionId,
      },
    });
    if (result.count === 0) {
      throw new NotFoundException(ERROR_AUTION_NOT_FOUND);
    }
    return { message: 'Auction removed from watchlist successfully' };
  }

  async getWatchlist(currUser: any): Promise<SearchAuctionResponseDto> {
    const watchlist = await this.prisma.watchlist.findMany({
      where: { userId: currUser.id },
      include: {
        auction: {
          select: {
            auctionId: true,
            title: true,
            startTime: true,
            endTime: true,
            startingPrice: true,
            currentPrice: true,
            minimumBidIncrement: true,
            status: true,
            auctionProducts: {
              select: {
                product: {
                  select: {
                    productId: true,
                    name: true,
                    stockQuantity: true,
                    status: true,
                  },
                },
              },
            },
          },
        },
      },
    });
    const data = watchlist.map(item => ({
      auctionId: item.auction.auctionId,
      title: item.auction.title,
      startTime: item.auction.startTime,
      endTime: item.auction.endTime,
      startingPrice: item.auction.startingPrice.toString(),
      currentPrice: item.auction.currentPrice.toString(),
      minimumBidIncrement: item.auction.minimumBidIncrement.toString(),
      status: item.auction.status,
    }));
    return {
      total: data.length,
      page: 0,
      size: data.length,
      data,
    };
  }

  async reopenAuction(reopenAuctionBodyDto: ReopenAuctionBodyDto): Promise<ReopenAuctionResponseDto> {
    const { auctionId } = reopenAuctionBodyDto;
    const auction = await this.prisma.auction.findUnique({
      where: { auctionId },
    });
    if (!auction) {
      throw new NotFoundException(ERROR_AUTION_NOT_FOUND);
    }

    if (auction.status !== AuctionStatus.CANCELED) {
      throw new BadRequestException(ERROR_AUTION_CANT_BE_REOPENED);
    }

    await this.prisma.auction.update({
      where: { auctionId },
      data: { status: AuctionStatus.PENDING },
    });

    return {
      auctionId,
      message: 'Auction reopened successfully, waiting for admin approval',
    };
  }

  async editAuction(auctionId: string, editAuctionBodyDto: EditAuctionBodyDto): Promise<EditAuctionResponseDto> {
    const auction = await this.prisma.auction.findUnique({
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
      throw new NotFoundException(ERROR_AUTION_NOT_FOUND);
    }

    if ((auction.status !== AuctionStatus.CANCELED) && (auction.status !== AuctionStatus.PENDING)) {
      throw new BadRequestException(ERROR_AUTION_CANT_BE_EDITED);
    }

    const now = new Date();
    if (editAuctionBodyDto.startTime && new Date(editAuctionBodyDto.startTime) < now) {
      const { statusCode, message, errorCode } =
        ERROR_AUCTION_START_TIME_IN_PAST(now);
      throw new BadRequestException({ statusCode, message, errorCode });
    }

    if (editAuctionBodyDto.startTime && editAuctionBodyDto.endTime && new Date(editAuctionBodyDto.startTime) >= new Date(editAuctionBodyDto.endTime)) {
      throw new BadRequestException(ERROR_INVALID_AUCTION_TIME);
    }

    const result = await this.prisma.$transaction(async (tx) => {
      // Hoàn trả stock quantity cho các sản phẩm cũ
      for (const auctionProduct of auction.auctionProducts) {
        await tx.product.update({
          where: { productId: auctionProduct.productId },
          data: {
            stockQuantity: { increment: auctionProduct.quantity },
          },
        });
      }

      // Xóa các auction products cũ
      await tx.auctionProduct.deleteMany({
        where: { auctionId },
      });

      // Xử lý products mới nếu có
      if (editAuctionBodyDto.products && editAuctionBodyDto.products.length > 0) {
        const productIds = editAuctionBodyDto.products.map((p) => p.productId);

        const foundProducts = await tx.product.findMany({
          where: { productId: { in: productIds } },
        });

        if (foundProducts.length !== productIds.length) {
          throw new NotFoundException(ERROR_PRODUCT_NOT_FOUND);
        }

        const productMap = new Map(
          foundProducts.map((product) => [product.productId, product]),
        );

        for (const { productId, quantity } of editAuctionBodyDto.products) {
          const product = productMap.get(productId);
          if (!product) continue;

          if (product.status !== 'ACTIVE') {
            const { statusCode, message, errorCode } =
              ERROR_PRODUCT_NOT_AVAILABLE(product.name);
            throw new BadRequestException({ statusCode, message, errorCode });
          }

          if (product.stockQuantity < quantity) {
            const { statusCode, message, errorCode } =
              ERROR_PRODUCT_STOCK_INSUFFICIENT(productId);
            throw new BadRequestException({ statusCode, message, errorCode });
          }

          await tx.product.update({
            where: { productId },
            data: {
              stockQuantity: { decrement: quantity },
            },
          });
        }

        // Tạo auction products mới
        await tx.auctionProduct.createMany({
          data: editAuctionBodyDto.products.map(({ productId, quantity }) => ({
            auctionId,
            productId,
            quantity,
          })),
        });
      }

      // Cập nhật auction
      const updatedAuction = await tx.auction.update({
        where: { auctionId },
        data: {
          ...(editAuctionBodyDto.title && { title: editAuctionBodyDto.title }),
          ...(editAuctionBodyDto.startTime && {
            startTime: new Date(editAuctionBodyDto.startTime),
            lastBidTime: new Date(editAuctionBodyDto.startTime)
          }),
          ...(editAuctionBodyDto.endTime && { endTime: new Date(editAuctionBodyDto.endTime) }),
          ...(editAuctionBodyDto.startingPrice && {
            startingPrice: editAuctionBodyDto.startingPrice,
            currentPrice: editAuctionBodyDto.startingPrice
          }),
          ...(editAuctionBodyDto.minimumBidIncrement && { minimumBidIncrement: editAuctionBodyDto.minimumBidIncrement }),
          status: AuctionStatus.PENDING, // Đặt lại status về PENDING để admin approve lại
        },
      });

      return updatedAuction;
    });

    return {
      auctionId: result.auctionId,
      message: 'Auction updated successfully, waiting for admin approval',
    };
  }
}
