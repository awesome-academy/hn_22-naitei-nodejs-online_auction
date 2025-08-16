import { IsOptional, IsEnum, IsUUID } from 'class-validator';

export class ExportProductsDto {
    @IsOptional()
    @IsEnum(['ACTIVE', 'INACTIVE'], { message: 'Status must be either ACTIVE or INACTIVE' })
    status?: 'ACTIVE' | 'INACTIVE';

    @IsOptional()
    @IsUUID('4', { message: 'sellerId must be a valid UUID' })
    sellerId?: string;
}

export interface ExportProductsResponseDto {
    filename: string;
    buffer: Buffer;
    contentType: string;
}
