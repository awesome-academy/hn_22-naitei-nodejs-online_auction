import { IsNotEmpty } from "class-validator";

export class ReopenAuctionBodyDto {
    @IsNotEmpty()
    auctionId!: string;
}

export class ReopenAuctionResponseDto {
    auctionId!: string;
    message!: string;
}
