import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  NotFoundException,
  Post,
  Query,
  Patch,
} from '@nestjs/common';
import { AuctionService } from './auction.service';
import { CreateAuctionDto } from './dtos/create-auction.body.dto';
import { CreateAuctionResponseDto } from './dtos/create-auction.response.dto';
import { Roles } from '@common/decorators/roles.decorator';
import { Role } from '@common/enums/role.enum';
import { SearchAuctionQueryDto } from './dtos/search-auction.query.dto';
import { SearchAuctionResponseDto } from './dtos/search-auction.response.dto';
import { Public } from '@common/decorators/public.decorator';
import { GetAuctionDetailResponseDto } from './dtos/get-auction-detail.response.dto';
import { ERROR_AUCTION_NOT_FOUND, MAX_AUCTIONS_NUMBERS } from './auction.constant';
import { CurrentUser } from '@common/decorators/user.decorator';
import { AddToWatchlistResponseDto } from './dtos/add-to-watchlist.response.dto';
import { AddToWatchlistDto } from './dtos/add-to-watchlist.body.dto';
import { RemoveFromWatchlistDto, RemoveFromWatchlistResponseDto } from './dtos/remove-from-watchlist.dto';
import { SortDirection } from '@common/types/sort-direction.enum';

@Controller('auctions')
export class AuctionController {
  constructor(private readonly auctionService: AuctionService) { }

  @Post()
  @Roles(Role.SELLER)
  @HttpCode(HttpStatus.CREATED)
  async createAuction(
    @Body() createAuctionDto: CreateAuctionDto,
    @CurrentUser() user: any,
  ): Promise<CreateAuctionResponseDto> {
    return this.auctionService.createAuction(user, createAuctionDto);
  }

  @Get()
  @Public()
  @HttpCode(HttpStatus.OK)
  async searchAuctions(
    @Query() query: SearchAuctionQueryDto,
  ): Promise<SearchAuctionResponseDto> {
    return this.auctionService.searchAuctions(query);
  }

  @Roles(Role.SELLER)
  @Get('my-auctions')
  async getMyAuctions(
    @CurrentUser() user: any,
  ): Promise<SearchAuctionResponseDto> {
    return this.auctionService.searchAuctions({
      sellerId: user.id,
      page: 0,
      size: MAX_AUCTIONS_NUMBERS,
      sortField: 'createdAt',
      sortDirection: SortDirection.DESC
    } as SearchAuctionQueryDto);
  }

  @Get(':auctionId')
  @Public()
  async getAuctionById(
    @Param('auctionId') auctionId: string,
  ): Promise<GetAuctionDetailResponseDto> {
    const auction = await this.auctionService.getAuctionById(auctionId);
    if (!auction) {
      throw new NotFoundException(ERROR_AUCTION_NOT_FOUND);
    }
    return auction;
  }

  @Patch('open/:auctionId')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.NO_CONTENT)
  async confirmAuction(@Param('auctionId') auctionId: string): Promise<void> {
    await this.auctionService.confirmAuction(auctionId);
  }

  @Patch('cancel/:auctionId')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.NO_CONTENT)
  async cancelAuction(@Param('auctionId') auctionId: string): Promise<void> {
    await this.auctionService.cancelAuction(auctionId);
  }

  @Patch('close/:auctionId')
  @Roles(Role.ADMIN, Role.SELLER)
  @HttpCode(HttpStatus.NO_CONTENT)
  async closeAuction(@Param('auctionId') auctionId: string): Promise<void> {
    await this.auctionService.closeAuction(auctionId);
  }

  @Roles(Role.BIDDER)
  @Post('add-to-watchlist')
  async addToWatchlist(
    @CurrentUser() user: any,
    @Body() addToWatchlistDto: AddToWatchlistDto,
  ): Promise<AddToWatchlistResponseDto> {
    return this.auctionService.addToWatchlist(user, addToWatchlistDto);
  }

  @Roles(Role.BIDDER)
  @Post('remove-from-watchlist')
  async removeFromWatchlist(
    @CurrentUser() user: any,
    @Body() removeFromWatchlistDto: RemoveFromWatchlistDto,
  ): Promise<RemoveFromWatchlistResponseDto> {
    return this.auctionService.removeFromWatchlist(user, removeFromWatchlistDto);
  }

  @Roles(Role.BIDDER)
  @Post('watchlist')
  async getWatchlist(
    @CurrentUser() user: any,
  ): Promise<SearchAuctionResponseDto> {
    return this.auctionService.getWatchlist(user);
  }
}
