export class AuctionCommentResponseDto {
  commentId!: string;
  auctionId!: string;
  content!: string;
  createdAt!: Date;
  updatedAt!: Date;
  user!: {
    userId: string;
    profile?: {
      firstName?: string;
      lastName?: string;
      avatar?: string;
    };
  };
}

export class GetAuctionCommentsResponseDto {
  data!: AuctionCommentResponseDto[];
  total!: number;
  page!: number;
  limit!: number;
  message!: string;
}
