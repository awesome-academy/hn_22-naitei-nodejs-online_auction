import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  UseGuards,
  Param,
  UseInterceptors,
  UploadedFile,
  Body,
  BadRequestException,
  ParseUUIDPipe,
  Query,
  Res,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { Response } from 'express';
import { ProductsService } from './products.service';
import JwtAuthGuard from '@common/guards/jwt.guard';
import { RoleGuard } from '@common/guards/role.guard';
import { Roles } from '@common/decorators/roles.decorator';
import { Role } from '@common/enums/role.enum';
import { UploadImageDto, UploadImageResponseDto } from './dtos/upload-image.dto';
import { CreateMultipleProductsDto } from './dtos/create-product.body.dto';
import { User } from '@prisma/client';
import { CurrentUser } from '@common/decorators/user.decorator';
import { UpdateMultipleProductsDto } from './dtos/update-product.body.dto';
import { ERROR_NO_PRODUCTS_PROVIDED } from '@common/constants/error.constant';
import { AuthType } from '@common/types/auth-type.enum';
import { Auth } from '@common/decorators/auth.decorator';
import { MultipleProductOwnerGuard } from '@common/guards/products-owner.guard';
import { GetProductResponseDto } from './dtos/get-product.response.dto';
import { ExportProductsDto } from './dtos/export-product.dto';

@Controller('products')
@UseGuards(JwtAuthGuard, RoleGuard)
export class ProductsController {
  constructor(private readonly productsService: ProductsService) { }

  // Upload product image endpoint
  @Post('upload')
  @Roles(Role.ADMIN, Role.SELLER)
  @UseInterceptors(FileInterceptor('image'))
  async uploadImage(
    @UploadedFile() file: Express.Multer.File,
    @Body() uploadImageDto?: UploadImageDto,
  ): Promise<UploadImageResponseDto> {
    if (!file) {
      throw new BadRequestException('No image file provided');
    }

    return await this.productsService.uploadProductImage(file, uploadImageDto);
  }

  @Post()
  async createMultipleProducts(@CurrentUser() currentUser: User, @Body() createMultipleProductsDto: CreateMultipleProductsDto) {
    console.log('Current User:', currentUser);
    return this.productsService.createMultipleProducts(currentUser, createMultipleProductsDto.products);
  }

  @Auth(AuthType.NONE)
  @Get('user/:userId')
  async getProductsByUserId(@Param('userId') userId: string) {
    return this.productsService.getProductsByUserId(userId);
  }

  @Get('my-products')
  @Roles(Role.ADMIN, Role.SELLER)
  async getMyProducts(@CurrentUser() currentUser: any) {
    return this.productsService.getProductsByUserId(currentUser.id);
  }

  @Get('my-products/active')
  @Roles(Role.ADMIN, Role.SELLER)
  async getMyActiveProducts(@CurrentUser() currentUser: any) {
    return this.productsService.getActiveProductsByUserId(currentUser.id);
  }

  @Get('export/excel')
  @Roles(Role.ADMIN, Role.SELLER)
  async exportProductsToExcel(
    @CurrentUser() currentUser: User,
    @Query() exportDto: ExportProductsDto,
    @Res() res: Response,
  ) {
    const exportResult = await this.productsService.exportProductsToExcel(currentUser, exportDto);

    res.setHeader('Content-Type', exportResult.contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${exportResult.filename}"`);
    res.setHeader('Content-Length', exportResult.buffer.length);

    res.send(exportResult.buffer);
  }

  @Put()
  @UseGuards(MultipleProductOwnerGuard)
  @Roles(Role.ADMIN, Role.SELLER)
  async updateMultipleProducts(@Body() updateMultipleProductsDto: UpdateMultipleProductsDto) {
    return this.productsService.updateMultipleProducts(updateMultipleProductsDto.products);
  }

  @Delete(':productIds')
  @UseGuards(MultipleProductOwnerGuard)
  @Roles(Role.ADMIN, Role.SELLER)
  async deleteMultipleProducts(@Param('productIds') productIds: string) {
    const ids = productIds.split(',').map(id => id.trim());
    if (ids.length === 0) {
      throw new BadRequestException(ERROR_NO_PRODUCTS_PROVIDED);
    }
    return this.productsService.deleteMultipleProducts(ids);
  }

  @Get(':id')
  async getProductById(
    @Param('id', new ParseUUIDPipe()) id: string,
  ): Promise<GetProductResponseDto> {
    return this.productsService.getProductById(id);
  }
}
