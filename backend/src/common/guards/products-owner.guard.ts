import { ERROR_NO_PRODUCTS_PROVIDED } from '@common/constants/error.constant';
import PrismaService from '@common/services/prisma.service';
import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { User } from '@prisma/client';


@Injectable()
export class MultipleProductOwnerGuard implements CanActivate {
  constructor(private prisma: PrismaService) { }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const currUser = request.user;
    const products = request.body?.products;
    const productIds = request.params.productIds?.split(',').map((id: string) => id.trim());

    if (productIds) {
      for (const productId of productIds) {
        const productData = await this.prisma.product.findUnique({
          where: { productId },
        });

        if (!productData) {
          throw new BadRequestException(`Product with ID ${productId} does not exist`);
        }

        if (productData.sellerId !== currUser.id) {
          throw new ForbiddenException('You do not have permission to delete this product');
        }
      }
      return true;
    }

    if (products) {
      for (const product of products) {
        const productData = await this.prisma.product.findUnique({
          where: { productId: product.productId },
        });

        if (!productData) {
          throw new BadRequestException(`Product with ID ${product.productId} does not exist`);
        }

        if (productData.sellerId !== currUser.id) {
          throw new ForbiddenException('You do not have permission to update this product');
        }
      }
      return true;
    }

    throw new BadRequestException(ERROR_NO_PRODUCTS_PROVIDED.message);
  }
}
