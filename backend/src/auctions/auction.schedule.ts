import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import PrismaService from '@common/services/prisma.service';
import { AuctionStatus } from '@prisma/client';

@Injectable()
export class AuctionScheduler {
  private readonly logger = new Logger(AuctionScheduler.name);

  constructor(private readonly prisma: PrismaService) {}

  @Cron(CronExpression.EVERY_MINUTE)
  async updateReadyAuctionsToOpen(): Promise<void> {
    const now = new Date();

    const readyAuctions = await this.prisma.auction.findMany({
      where: {
        status: AuctionStatus.READY,
        startTime: { lte: now },
      },
    });

    if (readyAuctions.length > 0) {
      await Promise.all(
        readyAuctions.map((auction) =>
          this.prisma.auction.update({
            where: { auctionId: auction.auctionId },
            data: { status: AuctionStatus.OPEN },
          }),
        ),
      );

      this.logger.log(
        `Opened ${readyAuctions.length} auctions that reached start time`,
      );
    }
  }

  @Cron(CronExpression.EVERY_MINUTE)
  async handleExpiredPendingAuctions(): Promise<void> {
    const now = new Date();

    const pendingAuctions = await this.prisma.auction.findMany({
      where: {
        status: AuctionStatus.PENDING,
        endTime: { lte: now },
      },
    });

    if (pendingAuctions.length > 0) {
      await Promise.all(
        pendingAuctions.map((auction) =>
          this.prisma.auction.update({
            where: { auctionId: auction.auctionId },
            data: { status: AuctionStatus.CLOSED },
          }),
        ),
      );

      this.logger.log(
        `Closed ${pendingAuctions.length} auctions that passed end time`,
      );
    }
  }

  @Cron(CronExpression.EVERY_MINUTE)
  async refundProductsForClosedAuctions(): Promise<void> {
    const now = new Date();

    const closedAuctions = await this.prisma.auction.findMany({
      where: {
        status: AuctionStatus.CLOSED,
        endTime: { lt: now },
      },
      include: { auctionProducts: true },
    });

    if (closedAuctions.length === 0) return;

    await this.prisma.$transaction(async (tx) => {
      for (const auction of closedAuctions) {
        for (const ap of auction.auctionProducts) {
          await tx.product.update({
            where: { productId: ap.productId },
            data: {
              stockQuantity: { increment: ap.quantity },
            },
          });
        }

        await tx.auction.update({
          where: { auctionId: auction.auctionId },
          data: { status: 'REFUND', updatedAt: new Date() },
        });

        this.logger.log(`Refunded products for auction ${auction.auctionId}`);
      }
    });
  }
}
