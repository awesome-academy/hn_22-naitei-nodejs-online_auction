import {
  Controller,
  Get,
  Patch,
  Param,
  Query,
  UseGuards,
  Body,
} from '@nestjs/common';
import JwtAuthGuard from '@common/guards/jwt.guard';
import { RoleGuard } from '@common/guards/role.guard';
import { Roles } from '@common/decorators/roles.decorator';
import { CurrentUser } from '@common/decorators/user.decorator';
import { Role } from '@common/enums/role.enum';
import { TokenPayload } from '@common/types/token-payload.interface';
import { ShippingService } from './shipping.service';
import { GetBidderShippingsQueryDto } from './dtos/get-bidder-shippings-query.dto';
import { GetBidderShippingsResponseDto } from './dtos/get-bidder-shippings-response.dto';
import { GetSellerShippingsQueryDto } from './dtos/get-seller-shippings-query.dto';
import { GetSellerShippingsResponseDto } from './dtos/get-seller-shippings-response.dto';
import { ConfirmDeliveryResponseDto } from './dtos/confirm-delivery-response.dto';
import { ConfirmShippedRequestDto } from './dtos/confirm-shipped-request.dto';
import { ConfirmShippedResponseDto } from './dtos/confirm-shipped-response.dto';

@Controller('shipping')
@UseGuards(JwtAuthGuard, RoleGuard)
export class ShippingController {
  constructor(private readonly shippingService: ShippingService) {}

  @Get('bidder')
  @Roles(Role.BIDDER)
  async getBidderShippings(
    @Query() query: GetBidderShippingsQueryDto,
    @CurrentUser() user: TokenPayload,
  ): Promise<GetBidderShippingsResponseDto> {
    return this.shippingService.getBidderShippings(user.id, query);
  }

  @Get('seller')
  @Roles(Role.SELLER)
  async getSellerShippings(
    @Query() query: GetSellerShippingsQueryDto,
    @CurrentUser() user: TokenPayload,
  ): Promise<GetSellerShippingsResponseDto> {
    return this.shippingService.getSellerShippings(user.id, query);
  }

  @Patch(':shippingId/confirm-delivery')
  @Roles(Role.BIDDER)
  async confirmDelivery(
    @Param('shippingId') shippingId: string,
    @CurrentUser() user: TokenPayload,
  ): Promise<ConfirmDeliveryResponseDto> {
    return this.shippingService.confirmDelivery(shippingId, user.id);
  }

  @Patch(':shippingId/confirm-shipped')
  @Roles(Role.SELLER)
  async confirmShipped(
    @Param('shippingId') shippingId: string,
    @Body() body: ConfirmShippedRequestDto,
    @CurrentUser() user: TokenPayload,
  ): Promise<ConfirmShippedResponseDto> {
    return await this.shippingService.confirmShipped(shippingId, user.id, body);
  }
}
