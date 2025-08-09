import { Injectable, NotFoundException, ForbiddenException, BadRequestException } from '@nestjs/common';
import PrismaService from '../common/services/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { Socket } from 'socket.io';
import { CreateMessageDto } from './dtos/create-message.dto';
import { CreateChatRoomDto } from './dtos/create-chat-room.dto';
import { ListMessageQueryDto } from './dtos/list-message-query.dto';
import { MessageType, MessageStatus } from '@prisma/client';
import {
  ERROR_CHAT_ROOM_NOT_FOUND,
  ERROR_NOT_ROOM_MEMBER,
  ERROR_FAILED_TO_SEND_MESSAGE,
  ERROR_INVALID_WEBSOCKET_TOKEN,
  SUCCESS_MESSAGE_SENT,
  SUCCESS_MESSAGES_MARKED_READ,
  CHAT_VALIDATION,
  ERROR_CANNOT_CHAT_WITH_SELF,
  WS_EVENTS,
  LIMIT_DEFAULT,
  OFFSET_DEFAULT,
  SUCCESS_NO_CHAT_ROOMS,
  SUCCESS_CHAT_ROOMS_RETRIEVED,
  ERROR_FAILED_TO_GET_CHAT_ROOMS,
  SUCCESS_CHAT_ROOM_CREATED_OR_RETRIEVED,
  ERROR_FAILED_TO_CREATE_CHAT_ROOM,
  ERROR_NO_ACCESS_TO_CHAT_ROOM,
  SUCCESS_MESSAGES_RETRIEVED,
  ERROR_FAILED_TO_GET_MESSAGES,
  ERROR_FAILED_TO_MARK_READ,
  SUCCESS_UNREAD_COUNT_RETRIEVED,
  ERROR_FAILED_TO_GET_UNREAD_COUNT,
  SUCCESS_CHAT_ROOM_DETAILS_RETRIEVED,
  ERROR_FAILED_TO_GET_CHAT_ROOM_DETAILS,
  ERROR_FAILED_TO_GET_OR_CREATE_CHAT_ROOM,
  ERROR_FAILED_TO_GET_MESSAGES_WITH_QUERY,
  ERROR_FAILED_TO_GET_UNREAD_MESSAGES_COUNT,
  ERROR_FAILED_TO_GET_USER_INFO,
  ERROR_FAILED_TO_DELETE_CHAT_ROOM,
  SUCCESS_CHAT_ROOM_DELETED,
} from './chat-constants';
import { ERROR_USER_NOT_FOUND } from '../common/constants/error.constant';
import TokenService from '../common/services/token.service';
import e from 'express';

@Injectable()
export class ChatService {
  private chatGateway: any = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenService: TokenService,
  ) { }

  setGateway(gateway: any) {
    this.chatGateway = gateway;
  }

  async handleGetChatRooms(userId: string) {
    try {
      const chatRooms = await this.prisma.chatRoom.findMany({
        where: {
          AND: [
            {
              OR: [
                { user1Id: userId },
                { user2Id: userId },
              ],
            },
            {
              OR: [
                {
                  AND: [
                    { user1Id: userId },
                    { deletedByUser1: false },
                  ],
                },
                {
                  AND: [
                    { user2Id: userId },
                    { deletedByUser2: false },
                  ],
                },
              ],
            },
          ],
        },
        include: {
          user1: {
            select: {
              userId: true,
              email: true,
              profile: {
                select: {
                  fullName: true,
                  profileImageUrl: true,
                },
              },
            },
          },
          user2: {
            select: {
              userId: true,
              email: true,
              profile: {
                select: {
                  fullName: true,
                  profileImageUrl: true,
                },
              },
            },
          },
          messages: {
            orderBy: { timestamp: 'desc' },
            take: 1,
            include: {
              sender: {
                select: {
                  userId: true,
                  email: true,
                  profile: {
                    select: {
                      fullName: true,
                      profileImageUrl: true,
                    },
                  },
                },
              },
            },
          },
        },
        orderBy: { updatedAt: 'desc' },
      });

      if (!chatRooms || chatRooms.length === 0) {
        return {
          success: true,
          data: [],
          message: SUCCESS_NO_CHAT_ROOMS.message,
        };
      }

      const roomsWithUnreadCount = await Promise.all(
        chatRooms.map(async (room) => {
          const unreadCount = await this.prisma.message.count({
            where: {
              chatRoomId: room.chatRoomId,
              senderId: { not: userId },
              status: { not: MessageStatus.READ },
            },
          });

          const otherUser = room.user1Id === userId ? room.user2 : room.user1;

          const lastMessage = await this.getLastMessageForUser(room.chatRoomId, userId);


          return {
            chatRoomId: room.chatRoomId,
            createdAt: room.createdAt,
            updatedAt: room.updatedAt,
            otherUser,
            lastMessage,
            unreadCount,
            isOneOnOne: true,
            participantCount: 2,
            deletionStatus: {
              deletedByUser1: room.deletedByUser1,
              deletedByUser2: room.deletedByUser2,
              user1DeletedAt: room.user1DeletedAt,
              user2DeletedAt: room.user2DeletedAt,
            },
          };
        })
      );

      return {
        success: true,
        data: roomsWithUnreadCount,
        message: SUCCESS_CHAT_ROOMS_RETRIEVED.message,
      };
    } catch (error) {
      throw new BadRequestException({
        success: false,
        message: ERROR_FAILED_TO_GET_CHAT_ROOMS.message,
      });
    }
  }

  async handleCreateOrGetChatRoom(createChatRoomDto: CreateChatRoomDto, currentUserId: string) {
    try {
      if (createChatRoomDto.otherUserId === currentUserId) {
        throw new BadRequestException({
          success: false,
          message: ERROR_CANNOT_CHAT_WITH_SELF.message,
        });
      }

      const otherUser = await this.getUserInfo(createChatRoomDto.otherUserId);
      if (!otherUser) {
        throw new NotFoundException({
          success: false,
          message: ERROR_USER_NOT_FOUND.message,
        });
      }

      const chatRoom = await this.getOrCreateChatRoom(
        currentUserId,
        createChatRoomDto.otherUserId
      );

      return {
        success: true,
        data: {
          chatRoom,
          otherUser,
          chatType: '1-on-1',
          participantCount: 2,
        },
        message: SUCCESS_CHAT_ROOM_CREATED_OR_RETRIEVED.message,
      };
    } catch (error) {
      if (error instanceof BadRequestException || error instanceof NotFoundException) {
        throw error;
      }
      throw new BadRequestException({
        success: false,
        message: ERROR_FAILED_TO_CREATE_CHAT_ROOM.message,
      });
    }
  }

  async handleGetMessages(chatRoomId: string, query: ListMessageQueryDto, currentUserId: string) {
    try {
      const hasAccess = await this.validateUserRoomAccess(chatRoomId, currentUserId);
      if (!hasAccess) {
        throw new ForbiddenException({
          success: false,
          message: ERROR_NO_ACCESS_TO_CHAT_ROOM.message,
        });
      }

      const messages = await this.getMessagesWithQuery(query, chatRoomId, currentUserId);

      return {
        success: true,
        data: messages,
        pagination: {
          limit: query.limit || LIMIT_DEFAULT,
          offset: query.offset || OFFSET_DEFAULT,
          total: messages.length,
        },
        message: SUCCESS_MESSAGES_RETRIEVED.message,
      };
    } catch (error) {
      if (error instanceof ForbiddenException) {
        throw error;
      }
      throw new BadRequestException({
        success: false,
        message: ERROR_FAILED_TO_GET_MESSAGES.message,
      });
    }
  }

  async handleSendMessageWithBroadcast(
    chatRoomId: string,
    createMessageDto: CreateMessageDto,
    currentUserId: string
  ): Promise<{
    success: boolean;
    data?: any;
    message: string;
  }> {
    try {
      const result = await this.handleSendMessage(chatRoomId, createMessageDto, currentUserId);

      if (result.success && this.chatGateway) {
        await this.broadcastNewMessage(result.data, chatRoomId, currentUserId);
      }

      return result;
    } catch (error) {
      throw error;
    }
  }

  async handleSendMessage(chatRoomId: string, createMessageDto: CreateMessageDto, currentUserId: string) {
    try {
      const hasAccess = await this.validateUserRoomAccess(chatRoomId, currentUserId);
      if (!hasAccess) {
        throw new ForbiddenException({
          success: false,
          message: ERROR_NOT_ROOM_MEMBER.message,
        });
      }

      const chatRoom = await this.prisma.chatRoom.findUnique({
        where: { chatRoomId },
      });

      if (chatRoom) {
        const isUser1 = chatRoom.user1Id === currentUserId;
        const isUser2 = chatRoom.user2Id === currentUserId;

        if ((isUser1 && chatRoom.deletedByUser1) || (isUser2 && chatRoom.deletedByUser2)) {
          const reactivateData: any = {};
          if (isUser1) {
            reactivateData.deletedByUser1 = false;
          } else if (isUser2) {
            reactivateData.deletedByUser2 = false;
          }

          await this.prisma.chatRoom.update({
            where: { chatRoomId },
            data: reactivateData,
          });
        }
      }

      if (createMessageDto.content && createMessageDto.content.length > CHAT_VALIDATION.MESSAGE.MAX_LENGTH) {
        throw new BadRequestException({
          success: false,
          message: CHAT_VALIDATION.MESSAGE.MESSAGE,
        });
      }

      const messageData = {
        ...createMessageDto,
        senderId: currentUserId,
        chatRoomId,
      };

      const message = await this.createMessage(messageData);

      if (this.chatGateway) {
        await this.broadcastToRoom(message, chatRoomId, currentUserId);
        await this.sendPrivateNotification(message, chatRoomId, currentUserId);
      }

      return {
        success: true,
        data: message,
        message: SUCCESS_MESSAGE_SENT.message,
      };
    } catch (error) {
      if (error instanceof ForbiddenException || error instanceof BadRequestException) {
        throw error;
      }
      throw new BadRequestException({
        success: false,
        message: ERROR_FAILED_TO_SEND_MESSAGE.message,
      });
    }
  }

  async handleMarkMessagesAsRead(chatRoomId: string, currentUserId: string) {
    try {
      const hasAccess = await this.validateUserRoomAccess(chatRoomId, currentUserId);
      if (!hasAccess) {
        throw new ForbiddenException({
          success: false,
          message: ERROR_NOT_ROOM_MEMBER,
        });
      }

      const result = await this.markMessagesAsRead(chatRoomId, currentUserId);

      if (this.chatGateway) {
        await this.broadcastMessagesRead(chatRoomId, currentUserId);
      }

      return {
        success: true,
        data: result,
        message: SUCCESS_MESSAGES_MARKED_READ.message,
      };
    } catch (error) {
      if (error instanceof ForbiddenException) {
        throw error;
      }
      throw new BadRequestException({
        success: false,
        message: ERROR_FAILED_TO_MARK_READ.message,
      });
    }
  }

  async handleGetUnreadCount(currentUserId: string) {
    try {
      const count = await this.getUnreadMessagesCount(currentUserId);

      return {
        success: true,
        data: { unreadCount: count },
        message: SUCCESS_UNREAD_COUNT_RETRIEVED.message,
      };
    } catch (error) {
      throw new BadRequestException({
        success: false,
        message: ERROR_FAILED_TO_GET_UNREAD_COUNT.message,
      });
    }
  }

  async handleGetChatRoomDetails(chatRoomId: string, currentUserId: string) {
    try {
      const hasAccess = await this.validateUserRoomAccess(chatRoomId, currentUserId);
      if (!hasAccess) {
        throw new ForbiddenException({
          success: false,
          message: ERROR_NO_ACCESS_TO_CHAT_ROOM.message,
        });
      }

      const chatRoom = await this.getChatRoomWithDetails(chatRoomId, currentUserId);

      return {
        success: true,
        data: chatRoom,
        message: SUCCESS_CHAT_ROOM_DETAILS_RETRIEVED.message,
      };
    } catch (error) {
      if (error instanceof ForbiddenException) {
        throw error;
      }
      throw new BadRequestException({
        success: false,
        message: ERROR_FAILED_TO_GET_CHAT_ROOM_DETAILS.message,
      });
    }
  }

  async handleDeleteChatRoom(chatRoomId: string, currentUserId: string) {
    try {
      const chatRoom = await this.prisma.chatRoom.findUnique({
        where: { chatRoomId },
      });

      if (!chatRoom) {
        throw new NotFoundException(ERROR_CHAT_ROOM_NOT_FOUND.message);
      }

      const hasAccess = await this.validateUserRoomAccess(chatRoomId, currentUserId);
      if (!hasAccess) {
        throw new ForbiddenException(ERROR_NOT_ROOM_MEMBER.message);
      }

      const isUser1 = chatRoom.user1Id === currentUserId;
      const isUser2 = chatRoom.user2Id === currentUserId;

      if ((isUser1 && chatRoom.deletedByUser1) || (isUser2 && chatRoom.deletedByUser2)) {
        throw new BadRequestException({
          success: false,
          message: 'You have already deleted this chat room',
        });
      }

      const updateData: any = {};
      if (isUser1) {
        updateData.deletedByUser1 = true;
        updateData.user1DeletedAt = new Date();
      } else if (isUser2) {
        updateData.deletedByUser2 = true;
        updateData.user2DeletedAt = new Date();
      }

      const updatedChatRoom = await this.prisma.chatRoom.update({
        where: { chatRoomId },
        data: updateData,
      });

      const bothDeleted = updatedChatRoom.deletedByUser1 && updatedChatRoom.deletedByUser2;

      if (bothDeleted) {
        await this.prisma.message.deleteMany({
          where: { chatRoomId },
        });

        await this.prisma.chatRoom.delete({
          where: { chatRoomId },
        });

        return {
          success: true,
          data: {
            chatRoomId,
            deletedAt: new Date().toISOString(),
            deletionType: 'hard_delete',
            reason: 'Both users deleted the chat room',
          },
          message: 'Chat room permanently deleted',
        };
      } else {
        return {
          success: true,
          data: {
            chatRoomId,
            deletedAt: new Date().toISOString(),
            deletionType: 'soft_delete',
            deletedBy: currentUserId,
            hiddenForUser: currentUserId,
          },
          message: SUCCESS_CHAT_ROOM_DELETED.message,
        };
      }
    } catch (error) {
      if (error instanceof NotFoundException ||
        error instanceof ForbiddenException ||
        error instanceof BadRequestException) {
        throw error;
      }
      throw new Error(ERROR_FAILED_TO_DELETE_CHAT_ROOM.message);
    }
  }

  private async broadcastToRoom(
    message: any,
    chatRoomId: string,
    senderId: string
  ): Promise<void> {
    if (!this.chatGateway) return;

    try {
      const roomTopic = `room.${chatRoomId}`;

      this.chatGateway.server.to(roomTopic).emit('room_message', {
        ...message,
        messageType: 'room_broadcast',
        timestamp: new Date().toISOString(),
        roomId: chatRoomId
      });
    } catch (error) {
      // Error handling without console log
    }
  }

  private async sendPrivateNotification(
    message: any,
    chatRoomId: string,
    senderId: string
  ): Promise<void> {
    try {
      const otherUser = await this.getOtherUserInRoom(chatRoomId, senderId);
      if (otherUser) {
        const userQueue = `user.${otherUser.userId}.queue`;

        this.chatGateway.server.to(userQueue).emit('private_message', {
          ...message,
          messageType: 'private_notification',
          timestamp: new Date().toISOString(),
          roomId: chatRoomId,
          notificationText: `New message from ${message.sender?.email || 'Unknown'}`
        });
      }
    } catch (error) {
    }
  }

  private async getOrCreateChatRoom(user1Id: string, user2Id: string) {
    try {
      const [firstUserId, secondUserId] = [user1Id, user2Id].sort();

      let chatRoom = await this.prisma.chatRoom.findFirst({
        where: {
          OR: [
            { user1Id: firstUserId, user2Id: secondUserId },
            { user1Id: secondUserId, user2Id: firstUserId },
          ],
        },
      });

      if (!chatRoom) {
        chatRoom = await this.prisma.chatRoom.create({
          data: {
            user1Id: firstUserId,
            user2Id: secondUserId,
          },
        });
      } else {
        const isUser1 = chatRoom.user1Id === user1Id;
        const isUser2 = chatRoom.user2Id === user1Id;

        if ((isUser1 && chatRoom.deletedByUser1) || (isUser2 && chatRoom.deletedByUser2)) {
          const reactivateData: any = {};
          if (isUser1) {
            reactivateData.deletedByUser1 = false;
            reactivateData.user1DeletedAt = new Date();
          } else if (isUser2) {
            reactivateData.deletedByUser2 = false;
            reactivateData.user2DeletedAt = new Date();
          }

          chatRoom = await this.prisma.chatRoom.update({
            where: { chatRoomId: chatRoom.chatRoomId },
            data: reactivateData,
          });
        }
      }

      return chatRoom;
    } catch (error) {
      throw new Error(ERROR_FAILED_TO_GET_OR_CREATE_CHAT_ROOM.message);
    }
  }

  private async getMessagesWithQuery(query: ListMessageQueryDto, chatRoomId: string, currentUserId?: string) {
    try {
      const limit = query.limit || LIMIT_DEFAULT;
      const offset = query.offset || OFFSET_DEFAULT;

      let whereClause: any = { chatRoomId };

      if (currentUserId) {
        const chatRoom = await this.prisma.chatRoom.findUnique({
          where: { chatRoomId },
        });

        if (chatRoom) {
          const isUser1 = chatRoom.user1Id === currentUserId;
          const isUser2 = chatRoom.user2Id === currentUserId;

          // Tìm theo thời gian xóa của người dùng
          if (isUser1 && chatRoom.user1DeletedAt) {
            whereClause.timestamp = { gt: chatRoom.user1DeletedAt };
          } else if (isUser2 && chatRoom.user2DeletedAt) {
            whereClause.timestamp = { gt: chatRoom.user2DeletedAt };
          }
        }
      }

      const messages = await this.prisma.message.findMany({
        where: whereClause,
        orderBy: { timestamp: 'desc' },
        take: limit,
        skip: offset,
        include: {
          sender: {
            select: {
              userId: true,
              email: true,
              profile: {
                select: {
                  fullName: true,
                  profileImageUrl: true,
                },
              },
            },
          },
        },
      });

      return messages.reverse();
    } catch (error) {
      throw new Error(ERROR_FAILED_TO_GET_MESSAGES_WITH_QUERY.message);
    }
  }

  private async createMessage(data: CreateMessageDto & { senderId: string; chatRoomId: string }) {
    try {
      const chatRoom = await this.prisma.chatRoom.findUnique({
        where: { chatRoomId: data.chatRoomId },
      });

      if (!chatRoom) {
        throw new NotFoundException(ERROR_CHAT_ROOM_NOT_FOUND.message);
      }

      if (chatRoom.user1Id !== data.senderId && chatRoom.user2Id !== data.senderId) {
        throw new ForbiddenException(ERROR_NOT_ROOM_MEMBER.message);
      }

      const message = await this.prisma.message.create({
        data: {
          content: data.content,
          senderId: data.senderId,
          chatRoomId: data.chatRoomId,
          type: data.type || MessageType.TEXT,
          fileUrl: data.fileUrl,
        },
        include: {
          sender: {
            select: {
              userId: true,
              email: true,
              profile: {
                select: {
                  fullName: true,
                  profileImageUrl: true,
                },
              },
            },
          },
        },
      });

      await this.prisma.chatRoom.update({
        where: { chatRoomId: data.chatRoomId },
        data: { updatedAt: new Date() },
      });

      return message;
    } catch (error) {
      if (error instanceof NotFoundException || error instanceof ForbiddenException) {
        throw error;
      }
      throw new Error(ERROR_FAILED_TO_SEND_MESSAGE.message);
    }
  }

  private async markMessagesAsRead(chatRoomId: string, userId: string) {
    try {
      await this.prisma.message.updateMany({
        where: {
          chatRoomId,
          senderId: { not: userId },
          status: { not: MessageStatus.READ },
        },
        data: {
          status: MessageStatus.READ,
        },
      });

      return {
        success: true,
        message: SUCCESS_MESSAGES_MARKED_READ.message,
      };
    } catch (error) {
      throw new Error(ERROR_FAILED_TO_MARK_READ.message);
    }
  }

  async getChatRoomWithDetails(chatRoomId: string, currentUserId: string) {
    try {
      const chatRoom = await this.prisma.chatRoom.findUnique({
        where: { chatRoomId },
        include: {
          user1: {
            select: {
              userId: true,
              email: true,
              profile: {
                select: {
                  fullName: true,
                  profileImageUrl: true,
                },
              },
            },
          },
          user2: {
            select: {
              userId: true,
              email: true,
              profile: {
                select: {
                  fullName: true,
                  profileImageUrl: true,
                },
              },
            },
          },
        },
      });

      if (!chatRoom) {
        throw new NotFoundException(ERROR_CHAT_ROOM_NOT_FOUND.message);
      }

      const messages = await this.getFilteredMessagesForUser(chatRoomId, currentUserId, LIMIT_DEFAULT);

      const unreadCount = await this.getUnreadCountForUser(chatRoomId, currentUserId);

      return {
        chatRoomId: chatRoom.chatRoomId,
        createdAt: chatRoom.createdAt,
        updatedAt: chatRoom.updatedAt,
        otherUser: chatRoom.user1Id === currentUserId ? chatRoom.user2 : chatRoom.user1,
        recentMessages: messages,
        unreadCount,
      };
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new Error(ERROR_FAILED_TO_GET_CHAT_ROOM_DETAILS.message);
    }
  }

  private async getFilteredMessagesForUser(chatRoomId: string, userId: string, limit: number = LIMIT_DEFAULT) {
    try {
      const chatRoom = await this.prisma.chatRoom.findUnique({
        where: { chatRoomId },
      });

      if (!chatRoom) return [];

      const isUser1 = chatRoom.user1Id === userId;
      const isUser2 = chatRoom.user2Id === userId;

      let whereClause: any = { chatRoomId };

      if (isUser1 && chatRoom.user1DeletedAt) {
        whereClause.timestamp = { gt: chatRoom.user1DeletedAt };
      } else if (isUser2 && chatRoom.user2DeletedAt) {
        whereClause.timestamp = { gt: chatRoom.user2DeletedAt };
      }

      const messages = await this.prisma.message.findMany({
        where: whereClause,
        orderBy: { timestamp: 'desc' },
        take: limit,
        include: {
          sender: {
            select: {
              userId: true,
              email: true,
              profile: {
                select: {
                  fullName: true,
                  profileImageUrl: true,
                },
              },
            },
          },
        },
      });

      return messages.reverse();
    } catch (error) {
      return [];
    }
  }

  async validateUser(client: Socket) {
    try {
      const token = client.handshake.auth?.token ||
        client.handshake.headers?.authorization?.replace('Bearer ', '') ||
        client.handshake.headers?.['authorization']?.replace('Bearer ', '') ||
        client.request?.headers?.authorization?.replace('Bearer ', '');

      if (!token) {
        throw new Error(ERROR_INVALID_WEBSOCKET_TOKEN.message);
      }

      let payload;
      try {
        payload = this.tokenService.verifyAccessToken(token);
      } catch (jwtError) {
        throw new Error(ERROR_INVALID_WEBSOCKET_TOKEN.message);
      }

      const user = await this.prisma.user.findUnique({
        where: { userId: (await payload).id },
        select: {
          userId: true,
          email: true,
          role: true
        },
      });

      if (!user) {
        throw new Error(ERROR_USER_NOT_FOUND.message);
      }

      return {
        id: user.userId,
        email: user.email,
        role: user.role
      };

    } catch (error) {
      throw error;
    }
  }

  private async getUnreadMessagesCount(userId: string): Promise<number> {
    try {
      const count = await this.prisma.message.count({
        where: {
          chatRoom: {
            OR: [
              { user1Id: userId },
              { user2Id: userId },
            ],
          },
          senderId: { not: userId },
          status: { not: MessageStatus.READ },
        },
      });

      return count;
    } catch (error) {
      throw new Error(ERROR_FAILED_TO_GET_UNREAD_MESSAGES_COUNT.message);
    }
  }

  async validateUserRoomAccess(chatRoomId: string, userId: string): Promise<boolean> {
    try {
      const chatRoom = await this.prisma.chatRoom.findUnique({
        where: { chatRoomId },
      });

      if (!chatRoom) {
        return false;
      }

      return chatRoom.user1Id === userId || chatRoom.user2Id === userId;
    } catch (error) {
      return false;
    }
  }

  private async broadcastNewMessage(
    message: any,
    chatRoomId: string,
    senderId: string
  ): Promise<void> {
    if (!this.chatGateway) return;

    const roomId = `room_${chatRoomId}`;

    const socketsInRoom = await this.chatGateway.server.in(roomId).fetchSockets();

    const receiverSockets = socketsInRoom.filter((socket: Socket) =>
      socket.data?.user?.id !== senderId
    );

    receiverSockets.forEach((socket: Socket) => {
      socket.emit(WS_EVENTS.NEW_MESSAGE, {
        ...message,
        broadcastType: 'new_message',
        timestamp: new Date().toISOString()
      });
    });

    await this.sendNotificationToOtherUser(chatRoomId, senderId, message);
  }

  private async sendNotificationToOtherUser(
    chatRoomId: string,
    senderId: string,
    message: any
  ): Promise<void> {
    try {
      const otherUser = await this.getOtherUserInRoom(chatRoomId, senderId);
      if (otherUser) {
        this.chatGateway.server.to(`user_${otherUser.userId}`).emit(WS_EVENTS.MESSAGE_NOTIFICATION, {
          chatRoomId,
          message,
          sender: {
            id: senderId,
            email: message.sender?.email,
          },
          notificationType: 'new_message',
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
    }
  }

  private async broadcastMessagesRead(
    chatRoomId: string,
    userId: string
  ): Promise<void> {
    if (!this.chatGateway) return;

    const roomId = `room_${chatRoomId}`;

    this.chatGateway.server.to(roomId).emit(WS_EVENTS.MESSAGES_READ, {
      chatRoomId,
      readBy: userId,
      success: true,
      message: SUCCESS_MESSAGES_MARKED_READ.message,
      timestamp: new Date().toISOString()
    });
  }

  private async getUserInfo(userId: string): Promise<{
    userId: string;
    email: string;
    profile: {
      fullName: string | null;
      profileImageUrl: string | null;
    } | null;
  }> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { userId },
        select: {
          userId: true,
          email: true,
          profile: {
            select: {
              fullName: true,
              profileImageUrl: true,
            },
          },
        },
      });

      if (!user) {
        throw new NotFoundException(ERROR_USER_NOT_FOUND.message);
      }

      return user;
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new Error(ERROR_FAILED_TO_GET_USER_INFO.message);
    }
  }

  private async getOtherUserInRoom(chatRoomId: string, currentUserId: string): Promise<{
    userId: string;
    email: string;
    profile: {
      fullName: string | null;
      profileImageUrl: string | null;
    } | null;
  } | null> {
    try {
      const chatRoom = await this.prisma.chatRoom.findUnique({
        where: { chatRoomId },
        include: {
          user1: {
            select: {
              userId: true,
              email: true,
              profile: {
                select: {
                  fullName: true,
                  profileImageUrl: true,
                },
              },
            },
          },
          user2: {
            select: {
              userId: true,
              email: true,
              profile: {
                select: {
                  fullName: true,
                  profileImageUrl: true,
                },
              },
            },
          },
        },
      });

      if (!chatRoom) {
        return null;
      }

      return chatRoom.user1Id === currentUserId ? chatRoom.user2 : chatRoom.user1;
    } catch (error) {
      return null;
    }
  }

  private async getLastMessageForUser(chatRoomId: string, userId: string) {
    try {
      const chatRoom = await this.prisma.chatRoom.findUnique({
        where: { chatRoomId },
      });

      if (!chatRoom) return null;

      const isUser1 = chatRoom.user1Id === userId;
      const isUser2 = chatRoom.user2Id === userId;

      let whereClause: any = { chatRoomId };

      if (isUser1 && chatRoom.user1DeletedAt) {
        whereClause.timestamp = { gt: chatRoom.user1DeletedAt };
      } else if (isUser2 && chatRoom.user2DeletedAt) {
        whereClause.timestamp = { gt: chatRoom.user2DeletedAt };
      }

      const message = await this.prisma.message.findFirst({
        where: whereClause,
        orderBy: { timestamp: 'desc' },
        include: {
          sender: {
            select: {
              userId: true,
              email: true,
              profile: {
                select: {
                  fullName: true,
                  profileImageUrl: true,
                },
              },
            },
          },
        },
      });

      return message;
    } catch (error) {
      return null;
    }
  }

  private async getUnreadCountForUser(chatRoomId: string, userId: string): Promise<number> {
    try {
      const chatRoom = await this.prisma.chatRoom.findUnique({
        where: { chatRoomId },
      });

      if (!chatRoom) return 0;

      const isUser1 = chatRoom.user1Id === userId;
      const isUser2 = chatRoom.user2Id === userId;

      let timestampFilter = {};
      if (isUser1 && chatRoom.user1DeletedAt) {
        timestampFilter = { timestamp: { gt: chatRoom.user1DeletedAt } };
      } else if (isUser2 && chatRoom.user2DeletedAt) {
        timestampFilter = { timestamp: { gt: chatRoom.user2DeletedAt } };
      }

      const count = await this.prisma.message.count({
        where: {
          chatRoomId,
          senderId: { not: userId },
          status: { not: MessageStatus.READ },
          ...timestampFilter,
        },
      });

      return count;
    } catch (error) {
      return 0;
    }
  }
}
