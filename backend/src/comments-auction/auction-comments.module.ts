import { Module } from '@nestjs/common';
import { AuctionCommentsController } from './auction-comments.controller';
import { AuctionCommentsService } from './auction-comments.service';
import { CommonModule } from '@common/common.module';

@Module({
  imports: [CommonModule],
  controllers: [AuctionCommentsController],
  providers: [AuctionCommentsService],
  exports: [AuctionCommentsService],
})
export class AuctionCommentsModule {}
