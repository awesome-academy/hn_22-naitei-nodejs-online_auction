export class MonthlyRevenueDto {
    month!: number;
    year!: number;
    revenue!: number;
}

export class TopProductDto {
    productId!: string;
    productName!: string;
    totalAuctions!: number;
    totalBids!: number;
    totalRevenue!: number;
    imageUrl?: string;
}

export class SellerStatisticsResponseDto {
    totalRevenue!: number;
    totalAuctions!: number;
    totalSoldProducts!: number;
    totalOrders!: number;
    monthlyRevenue!: MonthlyRevenueDto[];
    topProducts!: TopProductDto[];
    currentMonthRevenue!: number;
    previousMonthRevenue!: number;
    revenueGrowth!: number; // percentage
}
