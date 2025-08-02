import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ConflictException,
  ForbiddenException,
} from '@nestjs/common';
import PrismaService from '@common/services/prisma.service';
import { FollowResponseDto } from './dtos/follow.response.dto';
import { Role } from '@prisma/client';
import {
  ERROR_SELLER_NOT_FOUND,
  ERROR_ALREADY_FOLLOWING,
  ERROR_CANNOT_FOLLOW_YOURSELF,
  ERROR_FOLLOW_FAILED,
  ERROR_ONLY_BIDDERS_CAN_FOLLOW,
  ERROR_NOT_FOLLOWING,
  ERROR_UNFOLLOW_FAILED,
} from '@common/constants/error.constant';

@Injectable()
export class FollowsService {
  constructor(private prisma: PrismaService) {}

  async getFollowNumber(sellerId: string): Promise<{ followerCount: number }> {
    const seller = await this.prisma.user.findUnique({
      where: { userId: sellerId },
      select: { userId: true, role: true },
    });

    if (!seller) {
      throw new NotFoundException(ERROR_SELLER_NOT_FOUND);
    }

    if (seller.role !== Role.SELLER) {
      throw new BadRequestException(ERROR_SELLER_NOT_FOUND);
    }

    const followerCount = await this.prisma.follow.count({
      where: {
        sellerId: sellerId,
      },
    });

    return {
      followerCount,
    };
  }

  async followSeller(
    sellerId: string,
    currentUser: { id: string; email: string },
  ): Promise<FollowResponseDto> {
    const currentUserData = await this.prisma.user.findUnique({
      where: { userId: currentUser.id },
      select: { role: true },
    });

    if (!currentUserData || currentUserData.role !== Role.BIDDER) {
      throw new ForbiddenException(ERROR_ONLY_BIDDERS_CAN_FOLLOW);
    }

    if (sellerId === currentUser.id) {
      throw new BadRequestException(ERROR_CANNOT_FOLLOW_YOURSELF);
    }

    const seller = await this.prisma.user.findUnique({
      where: { userId: sellerId },
      select: { userId: true, role: true },
    });

    if (!seller) {
      throw new NotFoundException(ERROR_SELLER_NOT_FOUND);
    }

    if (seller.role !== Role.SELLER) {
      throw new BadRequestException(ERROR_SELLER_NOT_FOUND);
    }

    const existingFollow = await this.prisma.follow.findUnique({
      where: {
        followerId_sellerId: {
          followerId: currentUser.id,
          sellerId: sellerId,
        },
      },
    });

    if (existingFollow) {
      throw new ConflictException(ERROR_ALREADY_FOLLOWING);
    }

    try {
      const follow = await this.prisma.follow.create({
        data: {
          followerId: currentUser.id,
          sellerId: sellerId,
        },
      });

      return {
        followId: follow.followId,
        followerId: follow.followerId,
        sellerId: follow.sellerId,
        followedAt: follow.followedAt,
      };
    } catch {
      throw new BadRequestException(ERROR_FOLLOW_FAILED);
    }
  }

  async unfollowSeller(
    sellerId: string,
    currentUser: { id: string; email: string },
  ): Promise<{ message: string }> {
    const currentUserData = await this.prisma.user.findUnique({
      where: { userId: currentUser.id },
      select: { role: true },
    });

    if (!currentUserData || currentUserData.role !== Role.BIDDER) {
      throw new ForbiddenException(ERROR_ONLY_BIDDERS_CAN_FOLLOW);
    }

    if (sellerId === currentUser.id) {
      throw new BadRequestException(ERROR_CANNOT_FOLLOW_YOURSELF);
    }

    const seller = await this.prisma.user.findUnique({
      where: { userId: sellerId },
      select: { userId: true, role: true },
    });

    if (!seller) {
      throw new NotFoundException(ERROR_SELLER_NOT_FOUND);
    }

    if (seller.role !== Role.SELLER) {
      throw new BadRequestException(ERROR_SELLER_NOT_FOUND);
    }

    const existingFollow = await this.prisma.follow.findUnique({
      where: {
        followerId_sellerId: {
          followerId: currentUser.id,
          sellerId: sellerId,
        },
      },
    });

    if (!existingFollow) {
      throw new BadRequestException(ERROR_NOT_FOLLOWING);
    }

    try {
      await this.prisma.follow.delete({
        where: {
          followerId_sellerId: {
            followerId: currentUser.id,
            sellerId: sellerId,
          },
        },
      });

      return {
        message: 'Successfully unfollowed seller',
      };
    } catch {
      throw new BadRequestException(ERROR_UNFOLLOW_FAILED);
    }
  }

  async isFollowedByCurrentUser(
    sellerId: string,
    currentUser: { id: string; email: string },
  ): Promise<{ isFollowedByCurrentUser: boolean }> {
    const follow = await this.prisma.follow.findFirst({
      where: {
        followerId: currentUser.id,
        sellerId: sellerId,
      },
    });

    return {
      isFollowedByCurrentUser: !!follow,
    };
  }
}
