import { Controller, Get, Param, Put, Body, ForbiddenException, Post, Delete, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { CurrentUser } from '../common/decorators/user.decorator';
import { UserAccountInfoDto } from './dtos/profile.response.dto';
import { SellerAccountInfoDto } from './dtos/seller-profile.response.dto';
import { UpdateProfileDto } from './dtos/update-profile.body.dto';
import { AuthType } from '@common/types/auth-type.enum';
import { Auth } from '@common/decorators/auth.decorator';
import { CreateWarningDto } from './dtos/create.warning.dto';
import { ERROR_ACCESS_DENIED, ERROR_ADMIN_REQUIRED } from '@common/constants/error.constant';
import { UserWarningStatusDto } from './dtos/warning.response.dto';
import { RoleGuard } from '../common/guards/role.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { Role } from '../common/enums/role.enum';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get(':id/accountInfo')
  @Auth(AuthType.ACCESS_TOKEN)
  async getUserAccountInfo(
    @Param('id') userId: string,
    @CurrentUser() currentUser: { id: string; email: string },
  ): Promise<UserAccountInfoDto | SellerAccountInfoDto> {
    return this.usersService.getUserAccountInfo(userId, currentUser);
  }

  @Put(':id/profile')
  @Auth(AuthType.ACCESS_TOKEN)
  async updateProfile(
    @Param('id') userId: string,
    @Body() updateProfileDto: UpdateProfileDto,
    @CurrentUser() currentUser: { id: string; email: string },
  ): Promise<UserAccountInfoDto> {
    return await this.usersService.updateProfile(
      userId,
      updateProfileDto,
      currentUser,
    );
  }

  @Post('warnings/:id')
  @Auth(AuthType.ACCESS_TOKEN)
  @Roles(Role.ADMIN)
  @UseGuards(RoleGuard)
  async createWarning(
    @Param ('id') userId: string,
    @Body() createWarningDto: CreateWarningDto,
    @CurrentUser() admin: { id: string; email: string; role: string }
  ): Promise<UserWarningStatusDto> {

    return this.usersService.createWarning(userId, createWarningDto, admin.id);
  }

  @Get('warnings/:id')
  @Auth(AuthType.ACCESS_TOKEN)
  async getUserWarnings(@Param('id') userId: string,
    @CurrentUser() currentUser: { id: string; role: string }
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
    @CurrentUser() admin: { role: string }
  ) {

    return this.usersService.removeWarning(warningId);
  }
}
