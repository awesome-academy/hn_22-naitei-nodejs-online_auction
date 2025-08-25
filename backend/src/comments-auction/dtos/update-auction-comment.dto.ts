import { IsString, IsOptional, Length } from 'class-validator';
import {
  MAX_CONTENT_LENGTH,
  MIN_CONTENT_LENGTH,
} from '../auction-comments.constant';

export class UpdateAuctionCommentDto {
  @IsOptional()
  @IsString({ message: 'Content must be a string' })
  @Length(MIN_CONTENT_LENGTH, MAX_CONTENT_LENGTH, {
    message: `Content must be between ${MIN_CONTENT_LENGTH} and ${MAX_CONTENT_LENGTH} characters`,
  })
  content?: string;
}
