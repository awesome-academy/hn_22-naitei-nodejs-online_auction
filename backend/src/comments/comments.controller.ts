import {
  Controller,
  Post,
  Get,
  Put,
  Delete,
  Body,
  Param,
  UseGuards,
  Request,
  HttpStatus,
  HttpCode,
} from '@nestjs/common';
import { CommentsService } from './comments.service';
import { CreateCommentDto } from './dtos/create-comment.dto';
import { UpdateCommentDto } from './dtos/update-comment.dto';
import { CommentResponseDto, GetCommentsResponseDto } from './dtos/comment-response.dto';
import JwtAuthGuard from '@common/guards/jwt.guard';
import { RoleGuard } from '@common/guards/role.guard';
import { Roles } from '@common/decorators/roles.decorator';
import { Role } from '@common/enums/role.enum';

@Controller('comments')
export class CommentsController {
  constructor(private readonly commentsService: CommentsService) { }

  @Post()
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.BIDDER, Role.SELLER)
  @HttpCode(HttpStatus.CREATED)
  async createComment(
    @Request() req: any,
    @Body() createCommentDto: CreateCommentDto,
  ): Promise<CommentResponseDto> {
    return this.commentsService.createComment(req.user, createCommentDto);
  }

  @Get('product/:productId')
  async getCommentsByProductId(
    @Param('productId') productId: string,
  ): Promise<GetCommentsResponseDto> {
    return this.commentsService.getCommentsByProductId(productId);
  }

  @Get(':commentId')
  async getCommentById(
    @Param('commentId') commentId: string,
  ): Promise<CommentResponseDto> {
    return this.commentsService.getCommentById(commentId);
  }

  @Put(':commentId')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.BIDDER, Role.SELLER)
  async updateComment(
    @Request() req: any,
    @Param('commentId') commentId: string,
    @Body() updateCommentDto: UpdateCommentDto,
  ): Promise<CommentResponseDto> {
    return this.commentsService.updateComment(req.user, commentId, updateCommentDto);
  }

  @Delete(':commentId')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.BIDDER, Role.SELLER, Role.ADMIN)
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteComment(
    @Request() req: any,
    @Param('commentId') commentId: string,
  ): Promise<{ message: string }> {
    return this.commentsService.deleteComment(req.user, commentId);
  }
}
