import { IsString, IsNotEmpty, IsOptional, IsArray, IsUrl, MaxLength, ValidateNested, IsNumber, IsUUID } from 'class-validator';
import { Type } from 'class-transformer';
import { Product, ProductStatus } from '@prisma/client';

export class UpdateProductDto {

  @IsNotEmpty()
  @IsUUID()
  productId!: string;

  @IsString()
  @IsOptional()
  @MaxLength(255)
  name!: string;


  @IsOptional()
  @IsString()
  status?: ProductStatus;

  @IsOptional()
  @IsString()
  description?: string;

  @IsNumber()
  @IsOptional()
  stockQuantity!: number;

  @IsArray()
  @IsOptional()
  @IsUrl({}, { each: true })
  @Type(() => String)
  imageUrls!: string[];

  // Cap nhat category trong cac pull request sau nay
}


export class UpdateMultipleProductsDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => UpdateProductDto)
  products!: UpdateProductDto[];
}
