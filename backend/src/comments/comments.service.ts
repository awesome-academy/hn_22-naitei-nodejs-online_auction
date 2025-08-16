import { Injectable, NotFoundException, ForbiddenException, BadRequestException } from '@nestjs/common';
import PrismaService from '@common/services/prisma.service';
import { CreateCommentDto } from './dtos/create-comment.dto';
import { UpdateCommentDto } from './dtos/update-comment.dto';
import { CommentResponseDto, GetCommentsResponseDto } from './dtos/comment-response.dto';
import { User } from '@prisma/client';

@Injectable()
export class CommentsService {
    constructor(private readonly prisma: PrismaService) { }

    async createComment(user: User, createCommentDto: CreateCommentDto): Promise<CommentResponseDto> {
        // Kiểm tra product có tồn tại không
        const product = await this.prisma.product.findUnique({
            where: { productId: createCommentDto.productId },
        });

        if (!product) {
            throw new NotFoundException('Product not found');
        }

        // Tạo comment mới
        const comment = await this.prisma.productComment.create({
            data: {
                productId: createCommentDto.productId,
                userId: user.userId,
                content: createCommentDto.content,
                rating: createCommentDto.rating,
            },
            include: {
                user: {
                    include: {
                        profile: true,
                    },
                },
            },
        });

        return {
            commentId: comment.commentId,
            productId: comment.productId,
            userId: comment.userId,
            content: comment.content,
            rating: comment.rating || undefined,
            createdAt: comment.createdAt,
            updatedAt: comment.updatedAt,
            user: {
                userId: comment.user.userId,
                fullName: comment.user.profile?.fullName || undefined,
                profileImageUrl: comment.user.profile?.profileImageUrl || undefined,
            },
        };
    }

    async getCommentsByProductId(productId: string): Promise<GetCommentsResponseDto> {
        // Kiểm tra product có tồn tại không
        const product = await this.prisma.product.findUnique({
            where: { productId },
        });

        if (!product) {
            throw new NotFoundException('Product not found');
        }

        const comments = await this.prisma.productComment.findMany({
            where: { productId },
            include: {
                user: {
                    include: {
                        profile: true,
                    },
                },
            },
            orderBy: {
                createdAt: 'desc',
            },
        });

        const commentsResponse: CommentResponseDto[] = comments.map(comment => ({
            commentId: comment.commentId,
            productId: comment.productId,
            userId: comment.userId,
            content: comment.content,
            rating: comment.rating || undefined,
            createdAt: comment.createdAt,
            updatedAt: comment.updatedAt,
            user: {
                userId: comment.user.userId,
                fullName: comment.user.profile?.fullName || undefined,
                profileImageUrl: comment.user.profile?.profileImageUrl || undefined,
            },
        }));

        return {
            comments: commentsResponse,
            count: comments.length,
            message: 'Comments retrieved successfully',
        };
    }

    async updateComment(user: User, commentId: string, updateCommentDto: UpdateCommentDto): Promise<CommentResponseDto> {
        // Tìm comment
        const existingComment = await this.prisma.productComment.findUnique({
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
            throw new NotFoundException('Comment not found');
        }

        // Kiểm tra quyền sở hữu comment
        if (existingComment.userId !== user.userId) {
            throw new ForbiddenException('You can only update your own comments');
        }

        // Cập nhật comment
        const updatedComment = await this.prisma.productComment.update({
            where: { commentId },
            data: {
                ...(updateCommentDto.content && { content: updateCommentDto.content }),
                ...(updateCommentDto.rating !== undefined && { rating: updateCommentDto.rating }),
            },
            include: {
                user: {
                    include: {
                        profile: true,
                    },
                },
            },
        });

        return {
            commentId: updatedComment.commentId,
            productId: updatedComment.productId,
            userId: updatedComment.userId,
            content: updatedComment.content,
            rating: updatedComment.rating || undefined,
            createdAt: updatedComment.createdAt,
            updatedAt: updatedComment.updatedAt,
            user: {
                userId: updatedComment.user.userId,
                fullName: updatedComment.user.profile?.fullName || undefined,
                profileImageUrl: updatedComment.user.profile?.profileImageUrl || undefined,
            },
        };
    }

    async deleteComment(user: User, commentId: string): Promise<{ message: string }> {
        // Tìm comment
        const existingComment = await this.prisma.productComment.findUnique({
            where: { commentId },
        });

        if (!existingComment) {
            throw new NotFoundException('Comment not found');
        }

        // Kiểm tra quyền sở hữu comment hoặc admin
        if (existingComment.userId !== user.userId && user.role !== 'ADMIN') {
            throw new ForbiddenException('You can only delete your own comments');
        }

        // Xóa comment
        await this.prisma.productComment.delete({
            where: { commentId },
        });

        return {
            message: 'Comment deleted successfully',
        };
    }

    async getCommentById(commentId: string): Promise<CommentResponseDto> {
        const comment = await this.prisma.productComment.findUnique({
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
            throw new NotFoundException('Comment not found');
        }

        return {
            commentId: comment.commentId,
            productId: comment.productId,
            userId: comment.userId,
            content: comment.content,
            rating: comment.rating || undefined,
            createdAt: comment.createdAt,
            updatedAt: comment.updatedAt,
            user: {
                userId: comment.user.userId,
                fullName: comment.user.profile?.fullName || undefined,
                profileImageUrl: comment.user.profile?.profileImageUrl || undefined,
            },
        };
    }
}
