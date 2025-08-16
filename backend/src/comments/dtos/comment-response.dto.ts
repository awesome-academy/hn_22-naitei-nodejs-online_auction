export class CommentResponseDto {
    commentId!: string;
    productId!: string;
    userId!: string;
    content!: string;
    rating?: number;
    createdAt!: Date;
    updatedAt!: Date;
    user?: {
        userId: string;
        fullName?: string;
        profileImageUrl?: string;
    };
}

export class GetCommentsResponseDto {
    comments!: CommentResponseDto[];
    count!: number;
    message!: string;
}
