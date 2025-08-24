import { Controller, Get, Query, UseGuards, Patch, Param, Body } from '@nestjs/common';
import JwtAuthGuard from '@common/guards/jwt.guard';
import { RoleGuard } from '@common/guards/role.guard';
import { Roles } from '@common/decorators/roles.decorator';
import { CurrentUser } from '@common/decorators/user.decorator';
import { Role } from '@common/enums/role.enum';
import { TokenPayload } from '@common/types/token-payload.interface';
import { OrdersService } from './orders.service';
import { GetOrdersQueryDto } from './dtos/get-orders-query.dto';
import { GetOrdersResponseDto } from './dtos/get-orders-response.dto';
import { ConfirmShippedRequestDto } from '../shipping/dtos/confirm-shipped-request.dto';
import { ConfirmShippedResponseDto } from '../shipping/dtos/confirm-shipped-response.dto';

@Controller('orders')
@UseGuards(JwtAuthGuard, RoleGuard)
export class OrdersController {
  constructor(private readonly ordersService: OrdersService) {}

  @Get()
  @Roles(Role.ADMIN, Role.BIDDER, Role.SELLER)
  async getOrders(
    @Query() query: GetOrdersQueryDto,
    @CurrentUser() user: TokenPayload,
  ): Promise<GetOrdersResponseDto> {
    return this.ordersService.getOrders(user.id, user.role as Role, query);
  }

  @Patch(':orderId/confirm-shipped')
  @Roles(Role.SELLER)
  async confirmOrderShipped(
    @Param('orderId') orderId: string,
    @Body() body: ConfirmShippedRequestDto,
    @CurrentUser() user: TokenPayload,
  ): Promise<ConfirmShippedResponseDto> {
    return await this.ordersService.confirmOrderShipped(orderId, user.id, body);
  }
}
