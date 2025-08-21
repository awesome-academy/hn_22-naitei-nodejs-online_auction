import { Injectable, InternalServerErrorException } from '@nestjs/common';
import PrismaService from '@common/services/prisma.service';
import { StatisticsQueryDto } from './dtos/statistics-query.dto';
import { SellerStatisticsResponseDto, MonthlyRevenueDto, TopProductDto } from './dtos/seller-statistics-response.dto';
import { AuctionStatus, OrderStatus } from '@prisma/client';

@Injectable()
export class StatisticsService {
    constructor(private readonly prisma: PrismaService) { }

    async getSellerStatistics(
        sellerId: string,
        query: StatisticsQueryDto,
    ): Promise<SellerStatisticsResponseDto> {
        try {
            const { year, month, topProductsLimit = 10 } = query;
            const currentDate = new Date();
            const currentYear = year || currentDate.getFullYear();

            // Build date filters
            const dateFilter: any = {};
            if (year) {
                const startDate = new Date(year, 0, 1); // Start of year
                const endDate = new Date(year + 1, 0, 1); // Start of next year
                dateFilter.createdAt = {
                    gte: startDate,
                    lt: endDate,
                };
            }

            if (month && year) {
                const startDate = new Date(year, month - 1, 1); // Start of month
                const endDate = new Date(year, month, 1); // Start of next month
                dateFilter.createdAt = {
                    gte: startDate,
                    lt: endDate,
                };
            }

            // Get total revenue and statistics
            const totalStats = await this.getTotalStatistics(sellerId, dateFilter);

            // Get monthly revenue for the current year
            const monthlyRevenue = await this.getMonthlyRevenue(sellerId, currentYear);

            // Get top products by auction participation
            const topProducts = await this.getTopProducts(sellerId, topProductsLimit, dateFilter);

            // Get current and previous month revenue for growth calculation
            const { currentMonthRevenue, previousMonthRevenue, revenueGrowth } =
                await this.getRevenueGrowth(sellerId);

            return {
                ...totalStats,
                monthlyRevenue,
                topProducts,
                currentMonthRevenue,
                previousMonthRevenue,
                revenueGrowth,
            };
        } catch (error) {
            throw new InternalServerErrorException(
                `Failed to fetch seller statistics: ${error instanceof Error ? error.message : 'Unknown error'}`,
            );
        }
    }

    private async getTotalStatistics(sellerId: string, dateFilter: any) {
        // Get completed orders for the seller's auctions
        const ordersResult = await this.prisma.order.aggregate({
            where: {
                auction: {
                    sellerId,
                    status: AuctionStatus.COMPLETED,
                },
                status: {
                    in: [OrderStatus.COMPLETED, OrderStatus.PAID, OrderStatus.SHIPPING],
                },
                ...dateFilter,
            },
            _sum: {
                totalAmount: true,
            },
            _count: {
                orderId: true,
            },
        });

        // Get total auctions count
        const totalAuctions = await this.prisma.auction.count({
            where: {
                sellerId,
                status: AuctionStatus.COMPLETED,
                ...dateFilter,
            },
        });

        // Get total sold products count
        const totalSoldProducts = await this.prisma.auctionProduct.count({
            where: {
                auction: {
                    sellerId,
                    status: AuctionStatus.COMPLETED,
                    ...dateFilter,
                },
            },
        });

        return {
            totalRevenue: Number(ordersResult._sum.totalAmount || 0),
            totalAuctions,
            totalSoldProducts,
            totalOrders: ordersResult._count.orderId,
        };
    }

    private async getMonthlyRevenue(sellerId: string, year: number): Promise<MonthlyRevenueDto[]> {
        const startDate = new Date(year, 0, 1);
        const endDate = new Date(year + 1, 0, 1);

        const orders = await this.prisma.order.findMany({
            where: {
                auction: {
                    sellerId,
                    status: AuctionStatus.COMPLETED,
                },
                status: {
                    in: [OrderStatus.COMPLETED, OrderStatus.PAID, OrderStatus.SHIPPING],
                },
                createdAt: {
                    gte: startDate,
                    lt: endDate,
                },
            },
            select: {
                totalAmount: true,
                createdAt: true,
            },
        });

        // Group by month
        const monthlyData = new Map();
        for (let month = 1; month <= 12; month++) {
            monthlyData.set(month, 0);
        }

        orders.forEach((order) => {
            const month = order.createdAt.getMonth() + 1; // getMonth() returns 0-11
            const currentRevenue = monthlyData.get(month) || 0;
            monthlyData.set(month, currentRevenue + Number(order.totalAmount));
        });

        // Convert to array format
        const result: MonthlyRevenueDto[] = [];
        for (let month = 1; month <= 12; month++) {
            result.push({
                month,
                year,
                revenue: monthlyData.get(month) || 0,
            });
        }

        return result;
    }

    private async getTopProducts(
        sellerId: string,
        limit: number,
        dateFilter: any
    ): Promise<TopProductDto[]> {
        const whereClause: any = {
            auction: {
                sellerId,
                status: AuctionStatus.COMPLETED,
            },
        };

        if (dateFilter.createdAt) {
            whereClause.auction.createdAt = dateFilter.createdAt;
        }

        // Get auction products with aggregated data
        const auctionProducts = await this.prisma.auctionProduct.findMany({
            where: whereClause,
            include: {
                product: {
                    include: {
                        images: {
                            where: { isPrimary: true },
                            take: 1,
                        },
                    },
                },
                auction: {
                    include: {
                        bids: true,
                        orders: {
                            where: {
                                status: {
                                    in: [OrderStatus.COMPLETED, OrderStatus.PAID, OrderStatus.SHIPPING],
                                },
                            },
                        },
                    },
                },
            },
        });

        // Group by product and calculate metrics
        const productMetrics = new Map();

        auctionProducts.forEach((ap) => {
            const productId = ap.product.productId;

            if (!productMetrics.has(productId)) {
                productMetrics.set(productId, {
                    productId,
                    productName: ap.product.name,
                    imageUrl: ap.product.images[0]?.imageUrl || null,
                    auctions: new Set(),
                    totalBids: 0,
                    totalRevenue: 0,
                });
            }

            const metrics = productMetrics.get(productId);
            metrics.auctions.add(ap.auction.auctionId);
            metrics.totalBids += ap.auction.bids.length;
            metrics.totalRevenue += ap.auction.orders.reduce(
                (sum, order) => sum + Number(order.totalAmount),
                0
            );
        });

        // Convert to array and sort by total bids
        const sortedProducts = Array.from(productMetrics.values())
            .map((metrics) => ({
                productId: metrics.productId,
                productName: metrics.productName,
                totalAuctions: metrics.auctions.size,
                totalBids: metrics.totalBids,
                totalRevenue: metrics.totalRevenue,
                imageUrl: metrics.imageUrl,
            }))
            .sort((a, b) => {
                // Sort by total bids (desc), then by total auctions (desc), then by revenue (desc)
                if (b.totalBids !== a.totalBids) return b.totalBids - a.totalBids;
                if (b.totalAuctions !== a.totalAuctions) return b.totalAuctions - a.totalAuctions;
                return b.totalRevenue - a.totalRevenue;
            })
            .slice(0, limit);

        return sortedProducts;
    }

    private async getRevenueGrowth(sellerId: string) {
        const currentDate = new Date();
        const currentMonth = currentDate.getMonth();
        const currentYear = currentDate.getFullYear();

        // Current month revenue
        const currentMonthStart = new Date(currentYear, currentMonth, 1);
        const currentMonthEnd = new Date(currentYear, currentMonth + 1, 1);

        const currentMonthResult = await this.prisma.order.aggregate({
            where: {
                auction: {
                    sellerId,
                    status: AuctionStatus.COMPLETED,
                },
                status: {
                    in: [OrderStatus.COMPLETED, OrderStatus.PAID, OrderStatus.SHIPPING],
                },
                createdAt: {
                    gte: currentMonthStart,
                    lt: currentMonthEnd,
                },
            },
            _sum: {
                totalAmount: true,
            },
        });

        // Previous month revenue
        const previousMonthStart = new Date(currentYear, currentMonth - 1, 1);
        const previousMonthEnd = new Date(currentYear, currentMonth, 1);

        const previousMonthResult = await this.prisma.order.aggregate({
            where: {
                auction: {
                    sellerId,
                    status: AuctionStatus.COMPLETED,
                },
                status: {
                    in: [OrderStatus.COMPLETED, OrderStatus.PAID, OrderStatus.SHIPPING],
                },
                createdAt: {
                    gte: previousMonthStart,
                    lt: previousMonthEnd,
                },
            },
            _sum: {
                totalAmount: true,
            },
        });

        const currentMonthRevenue = Number(currentMonthResult._sum.totalAmount || 0);
        const previousMonthRevenue = Number(previousMonthResult._sum.totalAmount || 0);

        // Calculate percentage growth
        let revenueGrowth = 0;
        if (previousMonthRevenue > 0) {
            revenueGrowth = ((currentMonthRevenue - previousMonthRevenue) / previousMonthRevenue) * 100;
        } else if (currentMonthRevenue > 0) {
            revenueGrowth = 100; // 100% growth if previous was 0 but current is > 0
        }

        return {
            currentMonthRevenue,
            previousMonthRevenue,
            revenueGrowth: Math.round(revenueGrowth * 100) / 100, // Round to 2 decimal places
        };
    }
}
