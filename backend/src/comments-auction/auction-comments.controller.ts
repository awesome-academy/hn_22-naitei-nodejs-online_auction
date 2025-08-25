import {
  Controller,
  Post,
  Get,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpStatus,
  HttpCode,
  ParseIntPipe,
  DefaultValuePipe,
  ParseUUIDPipe,
} from '@nestjs/common';
import { AuctionCommentsService } from './auction-comments.service';
import { CreateAuctionCommentDto } from './dtos/create-auction-comment.dto';
import { UpdateAuctionCommentDto } from './dtos/update-auction-comment.dto';
import {
  AuctionCommentResponseDto,
  GetAuctionCommentsResponseDto,
} from './dtos/auction-comment-response.dto';
import JwtAuthGuard from '@common/guards/jwt.guard';
import { RoleGuard } from '@common/guards/role.guard';
import { Roles } from '@common/decorators/roles.decorator';
import { Role } from '@common/enums/role.enum';
import { CurrentUser } from '@common/decorators/user.decorator';
import { User } from '@prisma/client';
import { DEFAULT_PAGE, DEFAULT_LIMIT } from './auction-comments.constant';

@Controller('auction-comments')
export class AuctionCommentsController {
  constructor(private readonly commentsService: AuctionCommentsService) {}

  @Post()
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.BIDDER, Role.SELLER)
  @HttpCode(HttpStatus.CREATED)
  async createComment(
    @CurrentUser() user: User,
    @Body() createCommentDto: CreateAuctionCommentDto,
  ): Promise<AuctionCommentResponseDto> {
    return this.commentsService.createComment(user, createCommentDto);
  }

  @Get('auction/:auctionId')
  async getCommentsByAuctionId(
    @Param('auctionId', ParseUUIDPipe) auctionId: string,
    @Query('page', new DefaultValuePipe(DEFAULT_PAGE), ParseIntPipe) page: number,
    @Query('limit', new DefaultValuePipe(DEFAULT_LIMIT), ParseIntPipe) limit: number,
  ): Promise<GetAuctionCommentsResponseDto> {
    return this.commentsService.getCommentsByAuctionId(auctionId, page, limit);
  }

  @Get('user/:userId')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.BIDDER, Role.SELLER, Role.ADMIN)
  async getCommentsByUserId(
    @Param('userId', ParseUUIDPipe) userId: string,
    @Query('page', new DefaultValuePipe(DEFAULT_PAGE), ParseIntPipe) page: number,
    @Query('limit', new DefaultValuePipe(DEFAULT_LIMIT), ParseIntPipe) limit: number,
  ): Promise<GetAuctionCommentsResponseDto> {
    return this.commentsService.getCommentsByUserId(userId, page, limit);
  }

  @Get(':commentId')
  async getCommentById(
    @Param('commentId', ParseUUIDPipe) commentId: string,
  ): Promise<AuctionCommentResponseDto> {
    return this.commentsService.getCommentById(commentId);
  }

  @Put(':commentId')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.BIDDER, Role.SELLER, Role.ADMIN)
  async updateComment(
    @CurrentUser() user: User,
    @Param('commentId', ParseUUIDPipe) commentId: string,
    @Body() updateCommentDto: UpdateAuctionCommentDto,
  ): Promise<AuctionCommentResponseDto> {
    return this.commentsService.updateComment(
      user,
      commentId,
      updateCommentDto,
    );
  }

  @Delete(':commentId')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.BIDDER, Role.SELLER, Role.ADMIN)
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteComment(
    @CurrentUser() user: User,
    @Param('commentId', ParseUUIDPipe) commentId: string,
  ): Promise<{ message: string }> {
    return this.commentsService.deleteComment(user, commentId);
  }
}
