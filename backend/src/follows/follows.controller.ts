import { Controller, Post, Param, Get } from '@nestjs/common';
import { FollowsService } from './follows.service';
import { CurrentUser } from '@common/decorators/user.decorator';
import { FollowResponseDto } from './dtos/follow.response.dto';
import { AuthType } from '@common/types/auth-type.enum';
import { Auth } from '@common/decorators/auth.decorator';

@Controller('follows')
export class FollowsController {
  constructor(private readonly followsService: FollowsService) {}

  @Get(':sellerId/isFollowing')
  @Auth(AuthType.ACCESS_TOKEN)
  async getFollowStatus(
    @Param('sellerId') sellerId: string,
  ): Promise<{ followerCount: number }> {
    return this.followsService.getFollowNumber(sellerId);
  }

  @Post(':sellerId/follow')
  @Auth(AuthType.ACCESS_TOKEN)
  async followSeller(
    @Param('sellerId') sellerId: string,
    @CurrentUser() currentUser: { id: string; email: string },
  ): Promise<FollowResponseDto> {
    return this.followsService.followSeller(sellerId, currentUser);
  }

  @Post(':sellerId/unfollow')
  @Auth(AuthType.ACCESS_TOKEN)
  async unfollowSeller(
    @Param('sellerId') sellerId: string,
    @CurrentUser() currentUser: { id: string; email: string },
  ): Promise<{ message: string }> {
    return this.followsService.unfollowSeller(sellerId, currentUser);
  }
}
