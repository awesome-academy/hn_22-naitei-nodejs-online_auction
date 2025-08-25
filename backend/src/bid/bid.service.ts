import PrismaService from '@common/services/prisma.service';
import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import {
  ERROR_AUCTION_ALREADY_ENDED,
  ERROR_AUCTION_NOT_FOUND,
  ERROR_AUCTION_NOT_OPEN,
  ERROR_BID_ARRAY_INVALID,
  ERROR_BID_CONSECUTIVE,
  ERROR_BID_LAST_PHASE_LIMIT,
  ERROR_BID_LESS_THAN_MINIMUM,
  ERROR_BID_NOT_ELIGIBLE_LAST_PHASE,
  ERROR_BID_NOT_MULTIPLE_OF_INCREMENT,
  ERROR_BID_ONLY_HIDDEN_IN_LAST_PHASE,
  ERROR_BID_ONLY_LAST_10_MINUTES,
  ERROR_INSUFFICIENT_BALANCE,
} from './bid.constant';
import { BidResponseDto } from './dtos/bid.response.dto';
import { CreateBidBodyDto } from './dtos/create-bid.body.dto';
import { Auction } from '@prisma/client';

@Injectable()
export class BidService {
  constructor(private readonly prisma: PrismaService) { }

  async countBidsByAuction(auctionId: string): Promise<number> {
    const auction = await this.prisma.auction.findUnique({
      where: { auctionId },
    });
    if (!auction) throw new NotFoundException(ERROR_AUCTION_NOT_FOUND);

    const bidCount = await this.prisma.bid.count({
      where: { auctionId, isHidden: false },
    });

    return bidCount;
  }

  async getBidsByAuction(auctionId: string): Promise<BidResponseDto[]> {
    const auction = await this.prisma.auction.findUnique({
      where: { auctionId },
    });
    if (!auction) throw new NotFoundException(ERROR_AUCTION_NOT_FOUND);

    const bids = await this.prisma.bid.findMany({
      where: { auctionId },
      include: { user: { include: { profile: true } } },
      orderBy: { bidAmount: 'desc' },
    });

    return bids.map((bid) => ({
      bidId: bid.bidId,
      auctionId: bid.auctionId,
      userId: bid.userId,
      username: bid.user?.profile?.fullName || 'Unknown',
      bidAmount: Number(bid.bidAmount),
      status: bid.status,
      createdAt: bid.createdAt,
    }));
  }

  async placeHiddenBidsLast10Minutes(
    userId: string,
    dto: { auctionId: string; bidAmounts: number[] },
  ): Promise<BidResponseDto[]> {
    // 1. Validate auction and eligibility (including last 10 minutes and hidden bid limit)
    const { auction, isLast10Minutes } = await this.validateBid(
      dto.auctionId,
      userId,
    );

    if (!isLast10Minutes) {
      throw new BadRequestException(ERROR_BID_ONLY_LAST_10_MINUTES);
    }

    if (
      !dto.bidAmounts ||
      dto.bidAmounts.length === 0 ||
      dto.bidAmounts.length > 3
    ) {
      throw new BadRequestException(ERROR_BID_ARRAY_INVALID);
    }

    // Ensure all bidAmounts are unique
    const uniqueAmounts = new Set(dto.bidAmounts);
    if (uniqueAmounts.size !== dto.bidAmounts.length) {
      throw new BadRequestException(ERROR_BID_ARRAY_INVALID);
    }

    // 2. Get last public bid to determine minimum allowed bid
    const lastPublicBid = await this.prisma.bid.findFirst({
      where: { auctionId: dto.auctionId, isHidden: false },
      orderBy: { createdAt: 'desc' },
    });

    const minBidBase = lastPublicBid
      ? Number(lastPublicBid.bidAmount) + Number(auction.minimumBidIncrement)
      : Number(auction.currentPrice) + Number(auction.minimumBidIncrement);

    // 3. Validate each bidAmount
    for (const bidAmount of dto.bidAmounts) {
      if (bidAmount < minBidBase) {
        throw new BadRequestException(ERROR_BID_LESS_THAN_MINIMUM);
      }
      const diff = bidAmount - Number(auction.currentPrice);
      if (diff % Number(auction.minimumBidIncrement) !== 0) {
        throw new BadRequestException(ERROR_BID_NOT_MULTIPLE_OF_INCREMENT);
      }
    }

    // 4. Execute transaction: deduct max value only
    const maxBid = Math.max(...dto.bidAmounts);
    const user = await this.prisma.user.findUnique({ where: { userId } });
    if (!user || Number(user.walletBalance) < maxBid) {
      throw new BadRequestException(ERROR_INSUFFICIENT_BALANCE);
    }

    return this.prisma.$transaction(async (prisma) => {
      // a) Deduct max bid
      await prisma.user.update({
        where: { userId },
        data: { walletBalance: { decrement: maxBid } },
      });

      // b) Create wallet transaction for max bid only
      await prisma.walletTransaction.create({
        data: {
          userId,
          type: 'BID_PAYMENT',
          status: 'SUCCESS',
          amount: maxBid,
          balanceAfter: Number(user.walletBalance) - maxBid,
          auctionId: dto.auctionId,
        },
      });

      // c) Create all hidden bids
      const createdBids: BidResponseDto[] = [];
      for (const bidAmount of dto.bidAmounts) {
        const bid = await prisma.bid.create({
          data: {
            auctionId: dto.auctionId,
            userId,
            bidAmount,
            status: 'VALID',
            isHidden: true,
          },
          include: { user: { include: { profile: true } } },
        });

        createdBids.push({
          bidId: bid.bidId,
          auctionId: bid.auctionId,
          userId: bid.userId,
          username: bid.user?.profile?.fullName || 'Unknown',
          bidAmount: Number(bid.bidAmount),
          status: bid.status,
          createdAt: bid.createdAt,
        });
      }

      return createdBids;
    });
  }

  async placeBid(
    userId: string,
    dto: CreateBidBodyDto,
  ): Promise<BidResponseDto> {
    // 1. Validate the bid and get auction info, check if it's the last 10 minutes
    const { auction, isLast10Minutes } = await this.validateBid(
      dto.auctionId,
      userId,
    );
    if (isLast10Minutes) {
      throw new BadRequestException(ERROR_BID_ONLY_HIDDEN_IN_LAST_PHASE);
    }

    // 2. Get the most recent bid in this auction
    const lastBid = await this.prisma.bid.findFirst({
      where: { auctionId: dto.auctionId },
      orderBy: { createdAt: 'desc' },
    });

    // 3. Check if the user is trying to bid consecutively (only outside last 10 minutes)
    if (lastBid && lastBid.userId === userId && !isLast10Minutes) {
      throw new BadRequestException(ERROR_BID_CONSECUTIVE);
    }

    // 4. Determine the minimum allowed bid:
    // Normally, the minimum bid is currentPrice + minimumBidIncrement.
    // During the last 10 minutes, however, the bid only needs to be higher than the most recent public (non-hidden) bid
    // to allow "hidden" or out-of-order bids while still respecting the increment rule.
    const minBid =
      Number(auction.currentPrice) + Number(auction.minimumBidIncrement);
    if (dto.bidAmount < minBid) {
      throw new BadRequestException(ERROR_BID_LESS_THAN_MINIMUM);
    }

    // 5. Ensure bidAmount is a multiple of minimumBidIncrement
    const diff = dto.bidAmount - Number(auction.currentPrice);
    if (diff % Number(auction.minimumBidIncrement) !== 0) {
      throw new BadRequestException(ERROR_BID_NOT_MULTIPLE_OF_INCREMENT);
    }

    // 6. Check if the user has sufficient wallet balance
    const user = await this.prisma.user.findUnique({ where: { userId } });
    if (!user || Number(user.walletBalance) < dto.bidAmount) {
      throw new BadRequestException(ERROR_INSUFFICIENT_BALANCE);
    }

    // 7. Execute atomic transaction for bid
    const newBid = await this.prisma.$transaction(async (prisma) => {
      // a) Refund the previous bid if it exists
      if (lastBid) {
        const refundedBalance = Number(lastBid.bidAmount);
        await prisma.user.update({
          where: { userId: lastBid.userId },
          data: { walletBalance: { increment: refundedBalance } },
        });
        await prisma.walletTransaction.create({
          data: {
            userId: lastBid.userId,
            type: 'BID_REFUND',
            status: 'SUCCESS',
            amount: refundedBalance,
            balanceAfter: Number(user.walletBalance) + refundedBalance,
            auctionId: lastBid.auctionId,
            bidId: lastBid.bidId,
            description: 'Refund previous bid',
          },
        });
      }

      // b) Deduct the bid amount from user's wallet
      await prisma.user.update({
        where: { userId },
        data: { walletBalance: { decrement: dto.bidAmount } },
      });

      // c) Create a new bid
      const bid = await prisma.bid.create({
        data: {
          auctionId: dto.auctionId,
          userId,
          bidAmount: dto.bidAmount,
          status: 'VALID',
          isHidden: isLast10Minutes,
        },
        include: { user: { include: { profile: true } } },
      });

      await prisma.auction.update({
        where: { auctionId: dto.auctionId },
        data: {
          currentPrice: dto.bidAmount,
          bidCount: { increment: 1 },
          lastBidTime: new Date(),
        },
      });

      // d) Create wallet transaction
      await prisma.walletTransaction.create({
        data: {
          userId,
          type: 'BID_PAYMENT',
          status: 'SUCCESS',
          amount: dto.bidAmount,
          balanceAfter: Number(user.walletBalance) - dto.bidAmount,
        },
      });

      return bid;
    });

    // 8. Return data
    return {
      bidId: newBid.bidId,
      auctionId: newBid.auctionId,
      userId: newBid.userId,
      username: newBid.user?.profile?.fullName || 'Unknown',
      bidAmount: Number(newBid.bidAmount),
      status: newBid.status,
      createdAt: newBid.createdAt,
    };
  }

  private async validateBid(
    auctionId: string,
    userId: string,
  ): Promise<{
    auction: Auction;
    isLast10Minutes: boolean;
  }> {
    const auction = await this.prisma.auction.findUnique({
      where: { auctionId },
    });
    if (!auction) throw new NotFoundException(ERROR_AUCTION_NOT_FOUND);

    const now = new Date();
    if (auction.endTime < now)
      throw new BadRequestException(ERROR_AUCTION_ALREADY_ENDED);
    if (auction.startTime > now)
      throw new BadRequestException(ERROR_AUCTION_NOT_OPEN);

    const isLast10Minutes =
      auction.endTime.getTime() - now.getTime() <= 10 * 60 * 1000;
    if (isLast10Minutes) {
      // a) User must have placed a valid bid before
      const userPreviousBid = await this.prisma.bid.findFirst({
        where: { auctionId: auctionId, userId, status: 'VALID' },
      });
      if (!userPreviousBid) {
        throw new BadRequestException(ERROR_BID_NOT_ELIGIBLE_LAST_PHASE);
      }

      // b) User can only submit hidden bids once during the last 10 minutes
      const hiddenCount = await this.prisma.bid.count({
        where: { auctionId: auctionId, userId, isHidden: true },
      });
      if (hiddenCount > 0) {
        throw new BadRequestException(ERROR_BID_LAST_PHASE_LIMIT);
      }
    }

    return { auction, isLast10Minutes };
  }
}
