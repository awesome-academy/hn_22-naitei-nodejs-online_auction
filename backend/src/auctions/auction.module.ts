import { Module } from '@nestjs/common';
import { AuctionController } from './auction.controller';
import { AuctionService } from './auction.service';
import { CommonModule } from '@common/common.module';
import { BidModule } from '../bid/bid.module';
import { AuctionGateway } from './auction.gateway';
import { ScheduleModule } from '@nestjs/schedule';
import { AuctionScheduler } from './auction.schedule';

@Module({
  imports: [CommonModule, BidModule, ScheduleModule.forRoot()],
  controllers: [AuctionController],
  providers: [AuctionService, AuctionGateway, AuctionScheduler],
  exports: [AuctionService],
})
export class AuctionModule {}
