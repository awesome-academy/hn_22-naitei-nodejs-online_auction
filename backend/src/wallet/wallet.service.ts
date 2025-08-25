import PrismaService from '@common/services/prisma.service';
import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { TransactionStatus, TransactionType } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import {
  AddFundsDto,
  AdminAdjustBalanceDto,
  WalletBalanceResponseDto,
  WalletTransactionResponseDto
} from './dtos/wallet.dto';
import {
  WALLET_CONFIG,
  WALLET_ERRORS,
  TRANSACTION_DESCRIPTIONS,
  formatBidMinimumError,
  LIMIT_DEFAULT,
  PAGE_DEFAULT
} from './wallet.constants';
import { ListTransactionsDto } from './dtos/list-transactions.dto';

@Injectable()
export class WalletService {
  constructor(
    private readonly prisma: PrismaService,
  ) { }

  async addFundsToWallet(
    userId: string,
    addFundsDto: AddFundsDto,
  ): Promise<WalletTransactionResponseDto> {
    const { amount, description } = addFundsDto;

    if (amount < WALLET_CONFIG.MIN_DEPOSIT_AMOUNT || amount > WALLET_CONFIG.MAX_DEPOSIT_AMOUNT) {
      throw new BadRequestException(WALLET_ERRORS.INVALID_DEPOSIT_AMOUNT);
    }

    const result = await this.prisma.$transaction(async (tx) => {
      const updatedUser = await tx.user.update({
        where: { userId },
        data: {
          walletBalance: {
            increment: amount,
          },
        },
      });

      const transaction = await tx.walletTransaction.create({
        data: {
          userId,
          type: TransactionType.DEPOSIT,
          status: TransactionStatus.SUCCESS,
          amount: new Decimal(amount),
          balanceAfter: updatedUser.walletBalance,
          description: description || TRANSACTION_DESCRIPTIONS.DEPOSIT(amount),
        },
      });

      return transaction;
    });

    return {
      transactionId: result.transactionId,
      userId: result.userId,
      type: result.type,
      status: result.status,
      amount: result.amount.toString(),
      balanceAfter: result.balanceAfter.toString(),
      description: result.description || undefined,
      createdAt: result.createdAt,
    };
  }

  async getWalletBalance(userId: string): Promise<WalletBalanceResponseDto> {
    const user = await this.prisma.user.findUnique({
      where: { userId },
      select: { userId: true, walletBalance: true },
    });

    if (!user) {
      throw new NotFoundException(WALLET_ERRORS.USER_NOT_FOUND);
    }

    return {
      userId: user.userId,
      walletBalance: user.walletBalance.toString(),
      formattedBalance: new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(user.walletBalance.toNumber()),
    };
  }

  async getWalletTransactions(
    userId: string,
    query: ListTransactionsDto,
  ): Promise<{ transactions: WalletTransactionResponseDto[]; total: number; pagination: any }> {
    const {
      page = PAGE_DEFAULT,
      limit = LIMIT_DEFAULT,
      type,
      sortOrder = 'DESC',
      startDate,
      endDate,
      search
    } = query;

    const offset = (page - 1) * limit;

    const whereCondition: any = { userId };

    if (type) {
      whereCondition.type = type;
    }

    if (startDate || endDate) {
      whereCondition.createdAt = {};
      if (startDate) {
        whereCondition.createdAt.gte = startDate;
      }
      if (endDate) {
        whereCondition.createdAt.lte = endDate;
      }
    }

    if (search) {
      whereCondition.description = {
        contains: search,
        mode: 'insensitive',
      };
    }

    const [transactions, total] = await Promise.all([
      this.prisma.walletTransaction.findMany({
        where: whereCondition,
        orderBy: { createdAt: sortOrder.toLowerCase() as 'asc' | 'desc' },
        skip: offset,
        take: limit,
        include: {
          auction: {
            select: {
              auctionId: true,
              title: true,
            },
          },
          bid: {
            select: {
              bidId: true,
              bidAmount: true,
            },
          },
        },
      }),
      this.prisma.walletTransaction.count({
        where: whereCondition,
      }),
    ]);

    const totalPages = Math.ceil(total / limit);
    const hasNextPage = page < totalPages;
    const hasPrevPage = page > 1;

    return {
      transactions: transactions.map(tx => ({
        transactionId: tx.transactionId,
        userId: tx.userId,
        type: tx.type,
        status: tx.status,
        amount: tx.amount.toString(),
        balanceAfter: tx.balanceAfter.toString(),
        description: tx.description || undefined,
        createdAt: tx.createdAt,
        auction: tx.auction ? {
          auctionId: tx.auction.auctionId,
          title: tx.auction.title,
        } : undefined,
        bid: tx.bid ? {
          bidId: tx.bid.bidId,
          bidAmount: tx.bid.bidAmount.toString(),
        } : undefined,
      })),
      total,
      pagination: {
        currentPage: page,
        totalPages,
        limit,
        hasNextPage,
        hasPrevPage,
        totalRecords: total,
      },
    };
  }
}
