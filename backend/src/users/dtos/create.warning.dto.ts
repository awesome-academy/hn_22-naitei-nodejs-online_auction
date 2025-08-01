import { IsNotEmpty, IsString, IsOptional, MaxLength } from 'class-validator';

export class CreateWarningDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  reason!: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;
}
