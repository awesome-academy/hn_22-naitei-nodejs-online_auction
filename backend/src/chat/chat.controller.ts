import {
  Controller,
  Get,
  Post,
  Param,
  Query,
  Body,
  UseGuards,
  Delete,
} from '@nestjs/common';
import { ChatService } from './chat.service';
import { Auth } from '@common/decorators/auth.decorator';
import { AuthType } from '@common/types/auth-type.enum';
import { CurrentUser } from '@common/decorators/user.decorator';
import { CreateMessageDto } from './dtos/create-message.dto';
import { CreateChatRoomDto } from './dtos/create-chat-room.dto';
import { ListMessageQueryDto } from './dtos/list-message-query.dto';

@Controller('chat')
export class ChatController {
  constructor(private readonly chatService: ChatService) { }

  /**
   * Lấy danh sách chat rooms của user
   */
  @Get('rooms')
  @Auth(AuthType.ACCESS_TOKEN)
  async getChatRooms(@CurrentUser() user: { id: string }) {
    return await this.chatService.handleGetChatRooms(user.id);
  }

  /**
   * Tạo hoặc lấy chat room với user khác
   */
  @Post('rooms')
  @Auth(AuthType.ACCESS_TOKEN)
  async createOrGetChatRoom(
    @Body() createChatRoomDto: CreateChatRoomDto,
    @CurrentUser() user: { id: string },
  ) {
    return await this.chatService.handleCreateOrGetChatRoom(createChatRoomDto, user.id);
  }

  /**
   * Lấy tin nhắn trong chat room
   */
  @Get('rooms/:chatRoomId/messages')
  @Auth(AuthType.ACCESS_TOKEN)
  async getMessages(
    @CurrentUser() user: { id: string },
    @Param('chatRoomId') chatRoomId: string,
    @Query() query: ListMessageQueryDto,
  ) {
    return await this.chatService.handleGetMessages(chatRoomId, query, user.id);
  }

  /**
   * Gửi tin nhắn
   */
  @Post('rooms/:chatRoomId/messages')
  @Auth(AuthType.ACCESS_TOKEN)
  async sendMessage(
    @CurrentUser() user: { id: string },
    @Param('chatRoomId') chatRoomId: string,
    @Body() createMessageDto: CreateMessageDto,
  ) {
    return await this.chatService.handleSendMessage(chatRoomId, createMessageDto, user.id);
  }

  /**
   * Đánh dấu tin nhắn đã đọc
   */
  @Post('rooms/:chatRoomId/mark-read')
  @Auth(AuthType.ACCESS_TOKEN)
  async markMessagesAsRead(
    @CurrentUser() user: { id: string },
    @Param('chatRoomId') chatRoomId: string,
  ) {
    return await this.chatService.handleMarkMessagesAsRead(chatRoomId, user.id);
  }

  /**
   * Lấy số tin nhắn chưa đọc
   */
  @Get('unread-count')
  @Auth(AuthType.ACCESS_TOKEN)
  async getUnreadCount(@CurrentUser() user: { id: string }) {
    return await this.chatService.handleGetUnreadCount(user.id);
  }

  /**
   * Lấy chi tiết chat room
   */
  @Get('rooms/:chatRoomId')
  @Auth(AuthType.ACCESS_TOKEN)
  async getChatRoomDetails(
    @Param('chatRoomId') chatRoomId: string,
    @CurrentUser() user: { id: string },
  ) {
    return await this.chatService.handleGetChatRoomDetails(chatRoomId, user.id);
  }

  /**
   * Xoá đoạn chat
   */
  @Delete('rooms/:chatRoomId')
  @Auth(AuthType.ACCESS_TOKEN)
  async deleteChatRoom(
    @Param('chatRoomId') chatRoomId: string,
    @CurrentUser() user: { id: string },
  ) {
    return await this.chatService.handleDeleteChatRoom(chatRoomId, user.id);
  }
}
