import { IsString, IsOptional, IsInt, Min, Max } from 'class-validator';
import { MAX_STAR_RATE, MIN_STAR_RATE } from '../comments.constant';

export class UpdateCommentDto {
    @IsOptional()
    @IsString()
    content?: string;

    @IsOptional()
    @IsInt()
    @Min(MIN_STAR_RATE)
    @Max(MAX_STAR_RATE)
    rating?: number;
}
