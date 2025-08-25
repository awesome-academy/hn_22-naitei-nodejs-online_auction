import {
  ConnectedSocket,
  MessageBody,
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { BidService } from '../bid/bid.service';
import { Server, Socket } from 'socket.io';
import TokenService from '@common/services/token.service';
import {
  ERROR_INVALID_WEBSOCKET_TOKEN,
  ERROR_USER_NOT_FOUND,
  WS_EVENTS,
} from './auction.constant';
import PrismaService from '@common/services/prisma.service';
import { UseGuards } from '@nestjs/common';
import { WsJwtGuard } from '@common/guards/ws-jwt.guard';
import { AuctionService } from './auction.service';

@WebSocketGateway({
  cors: {
    origin: [
      process.env.WEBSOCKET_CORS_ORIGIN || 'http://localhost:5173',
      'http://localhost:3000',
    ],
    credentials: true,
  },
  namespace: '/auction',
  transports: ['websocket'],
})
export class AuctionGateway
  implements OnGatewayConnection, OnGatewayDisconnect
{
  @WebSocketServer()
  server!: Server;

  private readonly connectedUsers = new Map<string, string>();
  private readonly userSockets = new Map<string, string>();

  constructor(
    private readonly bidService: BidService,
    private readonly tokenService: TokenService,
    private readonly prisma: PrismaService,
    private readonly auctionService: AuctionService,
  ) {}

  async validateUser(client: Socket): Promise<{
    id: string;
    email: string;
    role: string;
  }> {
    const rawToken =
      (client.handshake.auth?.token as unknown) ||
      (client.handshake.headers?.authorization as unknown) ||
      (client.handshake.headers?.['authorization'] as unknown) ||
      (client.request?.headers?.authorization as unknown);

    const token =
      typeof rawToken === 'string' ? rawToken.replace('Bearer ', '') : '';

    if (!token) {
      throw new Error(ERROR_INVALID_WEBSOCKET_TOKEN.message);
    }

    let payload;
    try {
      payload = await this.tokenService.verifyAccessToken(token);
    } catch {
      throw new Error(ERROR_INVALID_WEBSOCKET_TOKEN.message);
    }

    const user = await this.prisma.user.findUnique({
      where: { userId: payload.id },
      select: {
        userId: true,
        email: true,
        role: true,
      },
    });

    if (!user) {
      throw new Error(ERROR_USER_NOT_FOUND.message);
    }

    return {
      id: user.userId,
      email: user.email,
      role: user.role,
    };
  }

  // --- Khi user kết nối vào websocket ---
  async handleConnection(client: Socket): Promise<void> {
    try {
      const user = await this.validateUser(client);
      client.data.user = user;
      this.connectedUsers.set(user.id, client.id);
      this.userSockets.set(client.id, user.id);

      const userQueue = `user.${user.id}.queue`;
      await client.join(userQueue);

      client.emit(WS_EVENTS.CONNECTION_SUCCESS, {
        message: 'Connected to chat server',
        userId: user.id,
        socketId: client.id,
        userQueue,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      client.emit(WS_EVENTS.ERROR, {
        message: error,
        timestamp: new Date().toISOString(),
      });
      client.disconnect(true);
    }
  }

  // --- Khi user disconnect ---
  handleDisconnect(client: Socket): void {
    const userId = this.userSockets.get(client.id);
    if (userId) {
      this.connectedUsers.delete(userId);
      this.userSockets.delete(client.id);
    }
  }

  // --- Sự kiện tham gia auction ---
  @SubscribeMessage(WS_EVENTS.JOIN_AUCTION)
  @UseGuards(WsJwtGuard)
  async handleJoinAuction(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { auctionId: string },
  ): Promise<void> {
    try {
      const { auctionId } = data;
      if (!auctionId) {
        client.emit(WS_EVENTS.ERROR, {
          message: 'auctionId is required',
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Tìm auction
      const auction = await this.prisma.auction.findUnique({
        where: { auctionId },
        select: { auctionId: true, status: true },
      });

      if (!auction) {
        client.emit(WS_EVENTS.ERROR, {
          message: 'Auction not found',
          auctionId,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Leave tất cả các room auction cũ
      const rooms = Array.from(client.rooms);
      for (const r of rooms) {
        if (r.startsWith('auction.')) {
          await client.leave(r);
        }
      }

      // Join room mới
      const room = `auction.${auctionId}`;
      await client.join(room);

      // Lấy danh sách user hiện tại sau khi join
      const usersInRoom = await this.getUsersInRoom(room);

      const bids = await this.bidService.getBidsByAuction(auctionId);

      client.emit(WS_EVENTS.BID_HISTORY, {
        auctionId,
        bidCount: bids.length,
        bidHistory: bids.map((b) => ({
          id: b.bidId,
          userId: b.userId,
          username: b.username,
          amount: b.bidAmount,
          timestamp: b.createdAt,
        })),
        timestamp: new Date().toISOString(),
      });

      // Thông báo cho chính user
      client.emit(WS_EVENTS.JOIN_AUCTION_SUCCESS, {
        message: `Joined auction ${auctionId}`,
        auctionId,
        userId: client.data.user?.id,
        participants: usersInRoom,
        participantCount: usersInRoom.length,
        socketId: client.id,
        timestamp: new Date().toISOString(),
      });

      this.server.to(room).emit(WS_EVENTS.USER_JOINED_AUCTION, {
        message: `User joined auction ${auctionId}`,
        auctionId,
        user: {
          id: client.data.user?.id,
          email: client.data.user?.email,
        },
        participants: usersInRoom,
        participantCount: usersInRoom.length,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      client.emit(WS_EVENTS.ERROR, {
        message: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });
    }
  }

  // --- Sự kiện rời auction ---
  @SubscribeMessage(WS_EVENTS.LEAVE_AUCTION)
  @UseGuards(WsJwtGuard)
  async handleLeaveAuction(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { auctionId: string },
  ): Promise<void> {
    try {
      const { auctionId } = data;
      if (!auctionId) {
        client.emit(WS_EVENTS.ERROR, {
          message: 'auctionId is required to leave',
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const room = `auction.${auctionId}`;

      // Kiểm tra client có đang ở room không
      if (!client.rooms.has(room)) {
        client.emit(WS_EVENTS.ERROR, {
          message: `You are not in auction ${auctionId}`,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Rời room
      await client.leave(room);

      // Lấy danh sách user còn lại
      const usersInRoom = await this.getUsersInRoom(room);

      // Thông báo cho chính client
      client.emit(WS_EVENTS.LEAVE_AUCTION_SUCCESS, {
        message: `Left auction ${auctionId}`,
        auctionId,
        userId: client.data.user?.id,
        socketId: client.id,
        participantCount: usersInRoom.length,
        participants: usersInRoom,
        timestamp: new Date().toISOString(),
      });

      // Dùng server broadcast cho các client còn lại
      this.server.to(room).emit(WS_EVENTS.USER_LEFT_AUCTION, {
        message: `User left auction ${auctionId}`,
        auctionId,
        user: {
          id: client.data.user?.id,
          email: client.data.user?.email,
        },
        participantCount: usersInRoom.length,
        participants: usersInRoom,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      client.emit(WS_EVENTS.ERROR, {
        message: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });
    }
  }

  // --- Sự kiện đặt bid ---
  @SubscribeMessage(WS_EVENTS.PLACE_BID)
  @UseGuards(WsJwtGuard)
  async handlePlaceBid(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { auctionId: string; bidAmount: number },
  ): Promise<void> {
    try {
      const { auctionId, bidAmount } = data;

      if (!auctionId || !bidAmount || bidAmount <= 0) {
        client.emit(WS_EVENTS.ERROR, {
          message: 'auctionId and bidAmount are required',
          timestamp: new Date().toISOString(),
        });
        return;
      }

      const auction = await this.prisma.auction.findUnique({
        where: { auctionId },
        select: { auctionId: true, status: true },
      });

      if (!auction) {
        client.emit(WS_EVENTS.ERROR, {
          message: 'Auction not found',
          auctionId,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Lưu bid vào DB qua BidService
      const bid = await this.bidService.placeBid(client.data.user.id, {
        auctionId,
        bidAmount,
      });

      // Lấy lịch sử bid của auction
      const bidCount = await this.bidService.countBidsByAuction(auctionId);

      const room = `auction.${auctionId}`;
      const usersInRoom = await this.getUsersInRoom(room);

      // Thông báo cho tất cả người trong room
      this.server.to(room).emit(WS_EVENTS.BID_ACCEPTED, {
        auctionId,
        bid: {
          id: bid.bidId,
          username: bid.username,
          userId: bid.userId,
          amount: bid.bidAmount,
          timestamp: bid.createdAt,
        },
        bidCount: bidCount,
        participantCount: usersInRoom.length,
        participants: usersInRoom,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      client.emit(WS_EVENTS.ERROR, {
        message: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });
    }
  }

  // --- Sự kiện kết thúc auction  ---
  @SubscribeMessage(WS_EVENTS.AUCTION_ENDED)
  @UseGuards(WsJwtGuard)
  async handleEndAuction(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { auctionId: string },
  ): Promise<void> {
    try {
      const { auctionId } = data;
      if (!auctionId) {
        client.emit(WS_EVENTS.ERROR, {
          message: 'auctionId is required to end',
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Gọi service để end auction
      const winner = await this.auctionService.endAuction(auctionId);

      const room = `auction.${auctionId}`;
      const usersInRoom = await this.getUsersInRoom(room);

      // Broadcast kết quả auction
      this.server.to(room).emit(WS_EVENTS.AUCTION_ENDED, {
        auctionId,
        winner,
        participants: usersInRoom,
        participantCount: usersInRoom.length,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      client.emit(WS_EVENTS.ERROR, {
        message: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });
    }
  }

  private async getUsersInRoom(
    room: string,
  ): Promise<{ id: string; email: string }[]> {
    const sockets = await this.server.in(room).fetchSockets();

    return sockets
      .map((s) => s.data.user)
      .filter(Boolean)
      .map((u) => ({ id: u.id, email: u.email }));
  }
}
