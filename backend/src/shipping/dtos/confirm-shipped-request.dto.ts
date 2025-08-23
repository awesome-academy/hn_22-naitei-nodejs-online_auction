import { IsOptional, IsString, MaxLength } from 'class-validator';

export class ConfirmShippedRequestDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  trackingNumber?: string;
}
