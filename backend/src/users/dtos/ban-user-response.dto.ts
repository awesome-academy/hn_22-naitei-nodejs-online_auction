export interface BanUserResponseDto {
  userId: string;
  email: string;
  isBanned: boolean;
  warningCount: number;
  bannedAt?: Date;
  message: string;
}
