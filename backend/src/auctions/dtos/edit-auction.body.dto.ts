export class EditAuctionBodyDto {
  title?: string;
  startTime?: Date;
  endTime?: Date;
  startingPrice?: number;
  minimumBidIncrement?: number;
  products?: { productId: string; quantity: number }[];
}
