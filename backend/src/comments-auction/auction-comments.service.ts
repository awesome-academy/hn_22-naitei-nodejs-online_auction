import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import PrismaService from '@common/services/prisma.service';
import { CreateAuctionCommentDto } from './dtos/create-auction-comment.dto';
import { UpdateAuctionCommentDto } from './dtos/update-auction-comment.dto';
import {
  AuctionCommentResponseDto,
  GetAuctionCommentsResponseDto,
} from './dtos/auction-comment-response.dto';
import { User, Role } from '@prisma/client';
import {
  AUCTION_COMMENT_ERRORS,
  AUCTION_COMMENT_MESSAGES,
  DEFAULT_PAGE,
  DEFAULT_LIMIT,
} from './auction-comments.constant';

@Injectable()
export class AuctionCommentsService {
  constructor(private readonly prisma: PrismaService) {}

  async createComment(
    user: User,
    createCommentDto: CreateAuctionCommentDto,
  ): Promise<AuctionCommentResponseDto> {
    const auction = await this.prisma.auction.findUnique({
      where: { auctionId: createCommentDto.auctionId },
    });

    if (!auction) {
      throw new NotFoundException(AUCTION_COMMENT_ERRORS.AUCTION_NOT_FOUND);
    }

    const comment = await this.prisma.auctionComment.create({
      data: {
        auctionId: createCommentDto.auctionId,
        userId: user.userId,
        content: createCommentDto.content,
      },
      include: {
        user: {
          include: {
            profile: true,
          },
        },
      },
    });

    return this.formatCommentResponse(comment);
  }

  async getCommentsByAuctionId(
    auctionId: string,
    page: number = DEFAULT_PAGE,
    limit: number = DEFAULT_LIMIT,
  ): Promise<GetAuctionCommentsResponseDto> {
    const auction = await this.prisma.auction.findUnique({
      where: { auctionId },
    });

    if (!auction) {
      throw new NotFoundException(AUCTION_COMMENT_ERRORS.AUCTION_NOT_FOUND);
    }

    const skip = (page - 1) * limit;

    const [comments, total] = await Promise.all([
      this.prisma.auctionComment.findMany({
        where: { auctionId },
        include: {
          user: {
            include: {
              profile: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.auctionComment.count({
        where: { auctionId },
      }),
    ]);

    const data = comments.map((comment) => this.formatCommentResponse(comment));

    return {
      data,
      total,
      page,
      limit,
      message: AUCTION_COMMENT_MESSAGES.COMMENTS_RETRIEVED,
    };
  }

  async getCommentById(commentId: string): Promise<AuctionCommentResponseDto> {
    const comment = await this.prisma.auctionComment.findUnique({
      where: { commentId },
      include: {
        user: {
          include: {
            profile: true,
          },
        },
      },
    });

    if (!comment) {
      throw new NotFoundException(AUCTION_COMMENT_ERRORS.COMMENT_NOT_FOUND);
    }

    return this.formatCommentResponse(comment);
  }

  async updateComment(
    user: User,
    commentId: string,
    updateCommentDto: UpdateAuctionCommentDto,
  ): Promise<AuctionCommentResponseDto> {
    const existingComment = await this.prisma.auctionComment.findUnique({
      where: { commentId },
      include: {
        user: {
          include: {
            profile: true,
          },
        },
      },
    });

    if (!existingComment) {
      throw new NotFoundException(AUCTION_COMMENT_ERRORS.COMMENT_NOT_FOUND);
    }

    if (existingComment.userId !== user.userId && user.role !== Role.ADMIN) {
      throw new ForbiddenException(AUCTION_COMMENT_ERRORS.UNAUTHORIZED_ACCESS);
    }

    const updatedComment = await this.prisma.auctionComment.update({
      where: { commentId },
      data: {
        content: updateCommentDto.content ?? existingComment.content,
      },
      include: {
        user: {
          include: {
            profile: true,
          },
        },
      },
    });

    return this.formatCommentResponse(updatedComment);
  }

  async deleteComment(
    user: User,
    commentId: string,
  ): Promise<{ message: string }> {
    const existingComment = await this.prisma.auctionComment.findUnique({
      where: { commentId },
    });

    if (!existingComment) {
      throw new NotFoundException(AUCTION_COMMENT_ERRORS.COMMENT_NOT_FOUND);
    }

    if (existingComment.userId !== user.userId && user.role !== Role.ADMIN) {
      throw new ForbiddenException(AUCTION_COMMENT_ERRORS.UNAUTHORIZED_ACCESS);
    }

    await this.prisma.auctionComment.delete({
      where: { commentId },
    });

    return { message: AUCTION_COMMENT_MESSAGES.COMMENT_DELETED };
  }

  async getCommentsByUserId(
    userId: string,
    page: number = DEFAULT_PAGE,
    limit: number = DEFAULT_LIMIT,
  ): Promise<GetAuctionCommentsResponseDto> {
    const skip = (page - 1) * limit;

    const [comments, total] = await Promise.all([
      this.prisma.auctionComment.findMany({
        where: { userId },
        include: {
          user: {
            include: {
              profile: true,
            },
          },
          auction: {
            select: {
              auctionId: true,
              title: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.auctionComment.count({
        where: { userId },
      }),
    ]);

    const data = comments.map((comment) => this.formatCommentResponse(comment));

    return {
      data,
      total,
      page,
      limit,
      message: AUCTION_COMMENT_MESSAGES.USER_COMMENTS_RETRIEVED,
    };
  }

  private formatCommentResponse(comment: any): AuctionCommentResponseDto {
    return {
      commentId: comment.commentId,
      auctionId: comment.auctionId,
      content: comment.content,
      createdAt: comment.createdAt,
      updatedAt: comment.updatedAt,
      user: {
        userId: comment.user.userId,
        profile: comment.user.profile
          ? {
              firstName: comment.user.profile.fullName?.split(' ')[0] || '',
              lastName: comment.user.profile.fullName?.split(' ').slice(1).join(' ') || '',
              avatar: comment.user.profile.profileImageUrl,
            }
          : undefined,
      },
    };
  }
}
