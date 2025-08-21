import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { MailerService } from '@nestjs-modules/mailer';
import PrismaService from '@common/services/prisma.service';
import { Role, AuctionStatus, OrderStatus } from '@prisma/client';

interface AdminSellerStats {
    sellerId: string;
    sellerName: string;
    sellerEmail: string;
    totalAuctions: number;
    completedAuctions: number;
    totalRevenue: number;
    totalProducts: number;
}

interface SellerAuctionStats {
    auctionId: string;
    title: string;
    status: AuctionStatus;
    startTime: Date;
    endTime: Date;
    currentPrice: number;
    bidCount: number;
    totalRevenue: number;
}

interface BidderStats {
    participatedAuctions: {
        auctionId: string;
        title: string;
        status: AuctionStatus;
        bidCount: number;
        highestBid: number;
        isWinner: boolean;
    }[];
    purchasedProducts: {
        orderId: string;
        auctionTitle: string;
        totalAmount: number;
        orderStatus: OrderStatus;
        purchaseDate: Date;
    }[];
    totalSpent: number;
    totalBids: number;
    wonAuctions: number;
}

@Injectable()
export class EmailSchedulerService {
    private readonly logger = new Logger(EmailSchedulerService.name);

    constructor(
        private readonly mailerService: MailerService,
        private readonly prisma: PrismaService,
    ) { }

    // Chạy vào 9:00 AM ngày 28 hàng tháng
    @Cron('0 9 28 * *')
    async sendMonthlyReports() {
        this.logger.log('Starting monthly report email sending...');

        try {
            const currentDate = new Date();
            const previousMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() - 1, 1);
            const currentMonthStart = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);

            // Gửi email cho từng role
            await Promise.all([
                this.sendAdminReports(previousMonth, currentMonthStart),
                this.sendSellerReports(previousMonth, currentMonthStart),
                this.sendBidderReports(previousMonth, currentMonthStart),
            ]);

            this.logger.log('Monthly report emails sent successfully');
        } catch (error) {
            this.logger.error('Failed to send monthly reports:', error);
        }
    }

    private async sendAdminReports(startDate: Date, endDate: Date) {
        const admins = await this.prisma.user.findMany({
            where: { role: Role.ADMIN },
            include: { profile: true },
        });

        const sellerStats = await this.getSellerStatsForAdmin(startDate, endDate);

        for (const admin of admins) {
            try {
                await this.mailerService.sendMail({
                    to: admin.email,
                    subject: `Monthly Seller Statistics Report - ${startDate.toLocaleDateString('vi-VN', { month: 'long', year: 'numeric' })}`,
                    template: 'admin-monthly-report',
                    context: {
                        adminName: admin.profile?.fullName || admin.email,
                        reportMonth: startDate.toLocaleDateString('vi-VN', { month: 'long', year: 'numeric' }),
                        sellerStats,
                        totalSellers: sellerStats.length,
                        totalAuctions: sellerStats.reduce((sum, s) => sum + s.totalAuctions, 0),
                        totalRevenue: sellerStats.reduce((sum, s) => sum + s.totalRevenue, 0),
                    },
                });

                this.logger.log(`Admin report sent to ${admin.email}`);
            } catch (error) {
                this.logger.error(`Failed to send admin report to ${admin.email}:`, error);
            }
        }
    }

    private async sendSellerReports(startDate: Date, endDate: Date) {
        const sellers = await this.prisma.user.findMany({
            where: { role: Role.SELLER },
            include: { profile: true },
        });

        for (const seller of sellers) {
            try {
                const sellerStats = await this.getSellerAuctionStats(seller.userId, startDate, endDate);

                await this.mailerService.sendMail({
                    to: seller.email,
                    subject: `Your Monthly Auction Report - ${startDate.toLocaleDateString('vi-VN', { month: 'long', year: 'numeric' })}`,
                    template: 'seller-monthly-report',
                    context: {
                        sellerName: seller.profile?.fullName || seller.email,
                        reportMonth: startDate.toLocaleDateString('vi-VN', { month: 'long', year: 'numeric' }),
                        auctions: sellerStats,
                        totalAuctions: sellerStats.length,
                        completedAuctions: sellerStats.filter(a => a.status === AuctionStatus.COMPLETED).length,
                        totalRevenue: sellerStats.reduce((sum, a) => sum + a.totalRevenue, 0),
                        totalBids: sellerStats.reduce((sum, a) => sum + a.bidCount, 0),
                    },
                });

                this.logger.log(`Seller report sent to ${seller.email}`);
            } catch (error) {
                this.logger.error(`Failed to send seller report to ${seller.email}:`, error);
            }
        }
    }

    private async sendBidderReports(startDate: Date, endDate: Date) {
        const bidders = await this.prisma.user.findMany({
            where: { role: Role.BIDDER },
            include: { profile: true },
        });

        for (const bidder of bidders) {
            try {
                const bidderStats = await this.getBidderStats(bidder.userId, startDate, endDate);

                // Chỉ gửi email nếu user có hoạt động trong tháng
                if (bidderStats.totalBids > 0 || bidderStats.purchasedProducts.length > 0) {
                    await this.mailerService.sendMail({
                        to: bidder.email,
                        subject: `Your Monthly Bidding Activity Report - ${startDate.toLocaleDateString('vi-VN', { month: 'long', year: 'numeric' })}`,
                        template: 'bidder-monthly-report',
                        context: {
                            bidderName: bidder.profile?.fullName || bidder.email,
                            reportMonth: startDate.toLocaleDateString('vi-VN', { month: 'long', year: 'numeric' }),
                            ...bidderStats,
                        },
                    });

                    this.logger.log(`Bidder report sent to ${bidder.email}`);
                }
            } catch (error) {
                this.logger.error(`Failed to send bidder report to ${bidder.email}:`, error);
            }
        }
    }

    private async getSellerStatsForAdmin(startDate: Date, endDate: Date): Promise<AdminSellerStats[]> {
        const sellers = await this.prisma.user.findMany({
            where: { role: Role.SELLER },
            include: {
                profile: true,
                createdAuctions: {
                    where: {
                        createdAt: {
                            gte: startDate,
                            lt: endDate,
                        },
                    },
                    include: {
                        auctionProducts: true,
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

        return sellers.map(seller => {
            const auctions = seller.createdAuctions;
            const completedAuctions = auctions.filter(a => a.status === AuctionStatus.COMPLETED);
            const totalRevenue = auctions.reduce((sum, auction) =>
                sum + auction.orders.reduce((orderSum, order) => orderSum + Number(order.totalAmount), 0), 0
            );
            const totalProducts = auctions.reduce((sum, auction) => sum + auction.auctionProducts.length, 0);

            return {
                sellerId: seller.userId,
                sellerName: seller.profile?.fullName || seller.email,
                sellerEmail: seller.email,
                totalAuctions: auctions.length,
                completedAuctions: completedAuctions.length,
                totalRevenue,
                totalProducts,
            };
        }).filter(stats => stats.totalAuctions > 0); // Chỉ bao gồm seller có tạo auction
    }

    private async getSellerAuctionStats(sellerId: string, startDate: Date, endDate: Date): Promise<SellerAuctionStats[]> {
        const auctions = await this.prisma.auction.findMany({
            where: {
                sellerId,
                createdAt: {
                    gte: startDate,
                    lt: endDate,
                },
            },
            include: {
                orders: {
                    where: {
                        status: {
                            in: [OrderStatus.COMPLETED, OrderStatus.PAID, OrderStatus.SHIPPING],
                        },
                    },
                },
                _count: {
                    select: { bids: true },
                },
            },
        });

        return auctions.map(auction => ({
            auctionId: auction.auctionId,
            title: auction.title,
            status: auction.status,
            startTime: auction.startTime,
            endTime: auction.endTime,
            currentPrice: Number(auction.currentPrice),
            bidCount: auction._count.bids,
            totalRevenue: auction.orders.reduce((sum, order) => sum + Number(order.totalAmount), 0),
        }));
    }

    private async getBidderStats(bidderId: string, startDate: Date, endDate: Date): Promise<BidderStats> {
        // Lấy các auction đã tham gia bid
        const participatedBids = await this.prisma.bid.findMany({
            where: {
                userId: bidderId,
                createdAt: {
                    gte: startDate,
                    lt: endDate,
                },
            },
            include: {
                auction: {
                    include: {
                        _count: {
                            select: { bids: true },
                        },
                    },
                },
            },
            distinct: ['auctionId'],
        });

        // Lấy highest bid cho mỗi auction
        const participatedAuctions = await Promise.all(
            participatedBids.map(async (bid) => {
                const highestBid = await this.prisma.bid.findFirst({
                    where: {
                        auctionId: bid.auctionId,
                        userId: bidderId,
                    },
                    orderBy: { bidAmount: 'desc' },
                });

                const isWinner = bid.auction.winnerId === bidderId;

                return {
                    auctionId: bid.auction.auctionId,
                    title: bid.auction.title,
                    status: bid.auction.status,
                    bidCount: bid.auction._count.bids,
                    highestBid: Number(highestBid?.bidAmount || 0),
                    isWinner,
                };
            })
        );

        // Lấy các sản phẩm đã mua
        const purchasedProducts = await this.prisma.order.findMany({
            where: {
                userId: bidderId,
                createdAt: {
                    gte: startDate,
                    lt: endDate,
                },
            },
            include: {
                auction: true,
            },
        });

        const totalSpent = purchasedProducts.reduce((sum, order) => sum + Number(order.totalAmount), 0);
        const totalBids = participatedBids.length;
        const wonAuctions = participatedAuctions.filter(a => a.isWinner).length;

        return {
            participatedAuctions,
            purchasedProducts: purchasedProducts.map(order => ({
                orderId: order.orderId,
                auctionTitle: order.auction.title,
                totalAmount: Number(order.totalAmount),
                orderStatus: order.status,
                purchaseDate: order.createdAt,
            })),
            totalSpent,
            totalBids,
            wonAuctions,
        };
    }

    // Test method để gửi ngay lập tức (có thể dùng để test)
    async sendTestReports() {
        this.logger.log('Sending test reports...');
        await this.sendMonthlyReports();
    }
}
