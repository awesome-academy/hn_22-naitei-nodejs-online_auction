import { Injectable, BadRequestException, NotFoundException } from '@nestjs/common';
import { UploadFileServiceS3 } from '@common/services/file.service';
import { UploadImageDto, UploadImageResponseDto } from './dtos/upload-image.dto';
import { CreateMultipleProductsDto, CreateProductDto } from './dtos/create-product.body.dto';
import PrismaService from '@common/services/prisma.service';
import { User } from '@prisma/client';
import { CreateMultipleProductsResponseDto, CreateProductResponseDto } from './dtos/create-product.response.dto';
import { UpdateProductDto } from './dtos/update-product.body.dto';
import { MultipleProductsResponseDto } from './dtos/product.response.dto';
import { GetProductResponseDto } from './dtos/get-product.response.dto';
import { randomUUID } from 'crypto';

@Injectable()
export class ProductsService {
  constructor(private readonly uploadFileService: UploadFileServiceS3, private prisma: PrismaService) { }

  async uploadProductImage(
    file: Express.Multer.File,
    uploadImageDto?: UploadImageDto,
  ): Promise<UploadImageResponseDto> {
    if (!file) {
      throw new BadRequestException('No file provided');
    }

    // Validate file type (only images)
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (!allowedMimeTypes.includes(file.mimetype)) {
      throw new BadRequestException('Only image files are allowed');
    }

    // Validate file size (max 5MB)
    const maxSize = 5 * 1024 * 1024; // 5MB
    if (file.size > maxSize) {
      throw new BadRequestException('File size must be less than 5MB');
    }

    try {
      const fileName = randomUUID();
      const imageUrl = await this.uploadFileService.uploadFileToPublicBucket(
        'products',
        {
          file,
          file_name: fileName,
        },
      );

      return {
        imageUrl,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new BadRequestException(`Failed to upload image: ${errorMessage}`);
    }
  }

  async getProductsByUserId(userId: string): Promise<MultipleProductsResponseDto> {
    const products = await this.prisma.product.findMany({
      where: { sellerId: userId },
      select: {
        productId: true,
        name: true,
        description: true,
        stockQuantity: true,
        status: true,
        images: {
          select: {
            imageUrl: true,
            isPrimary: true,
          },
        },
      },
    });
    return ({
      products: products.map(product => ({
        ...product,
        description: product.description ?? undefined,
      })),
      count: products.length,
      message: 'Products retrieved successfully',
    });
  }

  async getActiveProductsByUserId(userId: string): Promise<MultipleProductsResponseDto> {
    const products = await this.prisma.product.findMany({
      where: {
        sellerId: userId,
        status: 'ACTIVE',
        stockQuantity: { gt: 0 } 
      },
      select: {
        productId: true,
        name: true,
        description: true,
        stockQuantity: true,
        status: true,
        images: {
          select: {
            imageUrl: true,
            isPrimary: true,
          },
        },
      },
    });
    return ({
      products: products.map(product => ({
        ...product,
        description: product.description ?? undefined,
      })),
      count: products.length,
      message: 'Active products retrieved successfully',
    });
  }

  async createMultipleProducts(currUser: User, products: CreateProductDto[]): Promise<CreateMultipleProductsResponseDto> {
    const createdProducts: CreateProductResponseDto[] = [];
    for (const product of products) {
      const createdProd = await this.prisma.product.create({
        data: {
          name: product.name,
          description: product.description,
          stockQuantity: product.stockQuantity,
          status: 'INACTIVE',
          seller: {
            connect: { userId: (currUser as any).id || currUser.userId },
          },
        },
      });

      if (product.imageUrls && product.imageUrls.length > 0) {
        const imageData = product.imageUrls.map((url, index) => ({
          productId: createdProd.productId,
          imageUrl: url,
          isPrimary: index === 0, // Ảnh đầu tiên làm primary
        }));

        await this.prisma.productImage.createMany({
          data: imageData,
        });

        const createdProductWithImages = await this.prisma.product.findUnique({
          where: { productId: createdProd.productId },
          select: {
            productId: true,
            name: true,
            description: true,
            stockQuantity: true,
            status: true,
            images: {
              select: {
                imageUrl: true,
                isPrimary: true,
              },
            },
          }
        });

        if (createdProductWithImages) {
          createdProducts.push({
            ...createdProductWithImages,
            description: createdProductWithImages.description ?? undefined,
          });
        }
      }
    }

    return {
      products: createdProducts,
      count: createdProducts.length,
      message: 'Products created successfully',
    };
  }

  async updateMultipleProducts(data: UpdateProductDto[]): Promise<MultipleProductsResponseDto> {
    const updatedProducts: any[] = [];
    for (const product of data) {
      const updatedProduct = await this.prisma.product.update({
        where: { productId: product.productId },
        data: {
          name: product.name,
          description: product.description,
          stockQuantity: product.stockQuantity,
          status: product.status
        },
      });
      if (product.imageUrls && product.imageUrls.length > 0) {
        const imageData = product.imageUrls.map((url, index) => ({
          productId: product.productId,
          imageUrl: url,
          isPrimary: index === 0, // Ảnh đầu tiên làm primary
        }));

        // Xoá các ảnh cũ trước khi thêm ảnh mới
        await this.prisma.productImage.deleteMany({
          where: { productId: product.productId },
        });
        // Thêm ảnh mới
        await this.prisma.productImage.createMany({
          data: imageData,
        });
      }

      const updatedProductWithImages = await this.prisma.product.findUnique({
        where: { productId: product.productId },
        select: {
          productId: true,
          name: true,
          description: true,
          stockQuantity: true,
          status: true,
          images: {
            select: {
              imageUrl: true,
              isPrimary: true,
            },
          },
        }
      });

      if (updatedProductWithImages) {
        updatedProducts.push({
          ...updatedProductWithImages,
          description: updatedProductWithImages.description ?? undefined,
        });
      }
    }
    return {
      products: updatedProducts,
      count: updatedProducts.length,
      message: 'Products updated successfully',
    };
  }

  async deleteMultipleProducts(productIds: string[]): Promise<string> {
    try {
      await this.prisma.product.deleteMany({
        where: {
          productId: { in: productIds },
        },
      });
      return 'Products deleted successfully';
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new BadRequestException(`Failed to delete products: ${errorMessage}`);
    }
  }

  async getProductById(productId: string): Promise<GetProductResponseDto> {
    const product = await this.prisma.product.findUnique({
      where: { productId },
      select: {
        productId: true,
        name: true,
        description: true,
        stockQuantity: true,
        status: true,
        createdAt: true,
        updatedAt: true,
        images: {
          select: { imageId: true, imageUrl: true, isPrimary: true },
          orderBy: { isPrimary: 'desc' },
        },
        seller: {
          select: {
            userId: true,
            profile: { select: { fullName: true } },
          },
        },
        productCategories: {
          select: { category: { select: { categoryId: true, name: true } } },
        },
      },
    });

    if (!product) {
      throw new NotFoundException('Product not found');
    }

    return {
      productId: product.productId,
      name: product.name,
      description: product.description || undefined,
      status: product.status,
      createdAt: product.createdAt,
      updatedAt: product.updatedAt,
      images: product.images.map((image) => ({
        imageId: image.imageId,
        imageUrl: image.imageUrl,
        isPrimary: image.isPrimary,
      })),
      stockQuantity: product.stockQuantity,
      seller: {
        userId: product.seller.userId,
        fullName: product.seller.profile?.fullName || undefined,
      },
      categories: product.productCategories.map((pc) => ({
        categoryId: pc.category.categoryId,
        name: pc.category.name,
      })),
    };
  }
}
