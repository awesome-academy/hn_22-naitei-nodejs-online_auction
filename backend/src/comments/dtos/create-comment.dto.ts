import { IsString, IsNotEmpty, IsOptional, IsInt, Min, Max, IsUUID } from 'class-validator';

export class CreateCommentDto {
    @IsUUID()
    @IsNotEmpty()
    productId!: string;

    @IsString()
    @IsNotEmpty()
    content!: string;

    @IsOptional()
    @IsInt()
    @Min(1)
    @Max(5)
    rating?: number;
}
