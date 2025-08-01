import { ProductStatus } from '@prisma/client';

export class ProductImageResponseDto {
  imageUrl!: string;
  isPrimary!: boolean;
}

export class ProductResponseDto {
  productId!: string;
  name!: string;
  description?: string;
  stockQuantity!: number;
  status!: ProductStatus;
  images!: ProductImageResponseDto[];
}

export class MultipleProductsResponseDto {
  products!: ProductResponseDto[];
  count!: number;
  message!: string;
}