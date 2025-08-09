import {
  Controller,
  Post,
  Delete,
  Get,
  Param,
  Body,
  Query,
  ForbiddenException,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { CurrentUser } from '../common/decorators/user.decorator';
import { AuthType } from '@common/types/auth-type.enum';
import { Auth } from '@common/decorators/auth.decorator';
import { CreateWarningDto } from './dtos/create.warning.dto';
import { ERROR_ACCESS_DENIED } from '@common/constants/error.constant';
import { UserWarningStatusDto } from './dtos/warning.response.dto';
import { ListUsersQueryDto } from './dtos/list-users.dto';
import { ListUsersResponseDto } from './dtos/list-users-response.dto';
import { RoleGuard } from '../common/guards/role.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { Role } from '../common/enums/role.enum';
import {
  DEFAULT_LIMIT,
  DEFAULT_PAGE,
} from '@common/constants/pagination.constant';
import { BanUserResponseDto } from './dtos/ban-user-response.dto';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) { }

  @Get()
  @Auth(AuthType.ACCESS_TOKEN)
  @Roles(Role.ADMIN)
  @UseGuards(RoleGuard)
  async listUsers(
    @Query() query: ListUsersQueryDto,
  ): Promise<ListUsersResponseDto> {
    return this.usersService.listUsers(
      query.role,
      query.page || DEFAULT_PAGE,
      query.limit || DEFAULT_LIMIT,
    );
  }

  @Post('warnings/:id')
  @Auth(AuthType.ACCESS_TOKEN)
  @Roles(Role.ADMIN)
  @UseGuards(RoleGuard)
  async createWarning(
    @Param('id') userId: string,
    @Body() createWarningDto: CreateWarningDto,
    @CurrentUser() admin: { id: string; email: string; role: string },
  ): Promise<UserWarningStatusDto> {
    return this.usersService.createWarning(userId, createWarningDto, admin.id);
  }

  @Get('warnings/:id')
  @Auth(AuthType.ACCESS_TOKEN)
  async getUserWarnings(
    @Param('id') userId: string,
    @CurrentUser() currentUser: { id: string; role: string },
  ): Promise<UserWarningStatusDto> {
    // Admin có thể xem warning của bất kỳ user nào
    // User chỉ có thể xem warning của chính mình
    if (currentUser.role !== 'ADMIN' && currentUser.id !== userId) {
      throw new ForbiddenException(ERROR_ACCESS_DENIED);
    }

    return this.usersService.getUserWarnings(userId);
  }

  @Delete('warnings/:warningId')
  @Auth(AuthType.ACCESS_TOKEN)
  @Roles(Role.ADMIN)
  @UseGuards(RoleGuard)
  async removeWarning(
    @Param('warningId') warningId: string,
    @CurrentUser() _admin: { role: string },
  ): Promise<UserWarningStatusDto> {
    return this.usersService.removeWarning(warningId);
  }

  @Post('ban/:id')
  @Auth(AuthType.ACCESS_TOKEN)
  @Roles(Role.ADMIN)
  @UseGuards(RoleGuard)
  async banUser(
    @Param('id') userId: string,
    @CurrentUser() admin: { id: string; email: string; role: string },
  ): Promise<BanUserResponseDto> {
    return this.usersService.banUser(userId, admin.id);
  }

  @Post('unban/:id')
  @Auth(AuthType.ACCESS_TOKEN)
  @Roles(Role.ADMIN)
  @UseGuards(RoleGuard)
  async unbanUser(
    @Param('id') userId: string,
    @CurrentUser() admin: { id: string; email: string; role: string },
  ): Promise<BanUserResponseDto> {
    return this.usersService.unbanUser(userId, admin.id);
  }
}
