import { IsString, IsNotEmpty, IsUUID, Length } from 'class-validator';
import {
  MAX_CONTENT_LENGTH,
  MIN_CONTENT_LENGTH,
} from '../auction-comments.constant';

export class CreateAuctionCommentDto {
  @IsUUID(4, { message: 'Auction ID must be a valid UUID' })
  @IsNotEmpty({ message: 'Auction ID is required' })
  auctionId!: string;

  @IsString({ message: 'Content must be a string' })
  @IsNotEmpty({ message: 'Content is required' })
  @Length(MIN_CONTENT_LENGTH, MAX_CONTENT_LENGTH, {
    message: `Content must be between ${MIN_CONTENT_LENGTH} and ${MAX_CONTENT_LENGTH} characters`,
  })
  content!: string;
}
