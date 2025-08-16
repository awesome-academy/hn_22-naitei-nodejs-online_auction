import { Controller, Post, Param, Get, UseGuards } from '@nestjs/common';
import { FollowsService } from './follows.service';
import { CurrentUser } from '@common/decorators/user.decorator';
import { FollowResponseDto } from './dtos/follow.response.dto';
import { AuthType } from '@common/types/auth-type.enum';
import { Auth } from '@common/decorators/auth.decorator';
import { RoleGuard } from '@common/guards/role.guard';
import { Roles } from '@common/decorators/roles.decorator';
import { Role } from '@common/enums/role.enum';

@Controller('follows')
@UseGuards(RoleGuard)
export class FollowsController {
  constructor(private readonly followsService: FollowsService) { }

  @Get(':sellerId/isFollowing')
  @Auth(AuthType.ACCESS_TOKEN)
  @Roles(Role.BIDDER)
  async getFollowStatus(
    @Param('sellerId') sellerId: string,
  ): Promise<{ followerCount: number }> {
    return this.followsService.getFollowNumber(sellerId);
  }

  @Get(':sellerId/status')
  @Auth(AuthType.ACCESS_TOKEN)
  @Roles(Role.BIDDER)
  async checkFollowStatus(
    @Param('sellerId') sellerId: string,
    @CurrentUser() currentUser: { id: string; email: string },
  ): Promise<{ isFollowedByCurrentUser: boolean }> {
    return this.followsService.isFollowedByCurrentUser(sellerId, currentUser);
  }

  @Post(':sellerId/follow')
  @Auth(AuthType.ACCESS_TOKEN)
  @Roles(Role.BIDDER)
  async followSeller(
    @Param('sellerId') sellerId: string,
    @CurrentUser() currentUser: { id: string; email: string },
  ): Promise<FollowResponseDto> {
    return this.followsService.followSeller(sellerId, currentUser);
  }

  @Post(':sellerId/unfollow')
  @Auth(AuthType.ACCESS_TOKEN)
  @Roles(Role.BIDDER)
  async unfollowSeller(
    @Param('sellerId') sellerId: string,
    @CurrentUser() currentUser: { id: string; email: string },
  ): Promise<{ message: string }> {
    return this.followsService.unfollowSeller(sellerId, currentUser);
  }
}
