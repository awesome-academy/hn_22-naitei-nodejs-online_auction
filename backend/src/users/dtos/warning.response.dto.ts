export class WarningResponseDto {
  warningId!: string;
  userId!: string;
  adminId!: string;
  reason!: string;
  description?: string | null;
  createdAt!: Date;
}

export class UserWarningStatusDto {
  userId!: string;
  warningCount!: number;
  isBanned!: boolean;
  warnings!: WarningResponseDto[];
  message!: string;
}
