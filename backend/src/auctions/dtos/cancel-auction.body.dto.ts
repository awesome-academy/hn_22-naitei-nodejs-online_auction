import { IsNotEmpty, IsString } from "class-validator";

export class CancelAuctionDto {
    @IsNotEmpty()
    @IsString()
    auctionId!: string;

    @IsNotEmpty()
    @IsString()
    reason!: string;
}
