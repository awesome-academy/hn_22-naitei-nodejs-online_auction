import React from "react";
import { Title, LoadingSpinner } from "@/components/ui/index.js";
import StatisticsCard from "@/components/ui/StatisticsCard.jsx";
import MonthlyRevenueChart from "@/components/ui/MonthlyRevenueChart.jsx";
import TopProductsTable from "@/components/ui/TopProductsTable.jsx";
import { useSellerStatistics } from "@/hooks/useSellerStatistics.js";
import { useUser } from "@/contexts/UserContext.jsx";
import {
    IoCashOutline,
    IoTrendingUpOutline,
    IoReceiptOutline,
    IoStatsChartOutline,
    IoRefreshOutline,
    IoChevronDownOutline
} from "react-icons/io5";

const SellerStatistics = () => {
    const { user } = useUser();
    const {
        statistics,
        loading,
        error,
        selectedYear,
        setSelectedYear,
        selectedMonth,
        setSelectedMonth,
        topProductsLimit,
        setTopProductsLimit,
        refreshStatistics,
        formatCurrency,
        formatNumber,
        getMonthName,
        getGrowthIndicator,
        getYearOptions,
    } = useSellerStatistics();

    // Redirect if not seller
    if (user?.role !== "SELLER") {
        return (
            <div className="max-w-7xl mx-auto p-6">
                <div className="text-center py-8">
                    <p className="text-gray-600">This section is only available for sellers.</p>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="max-w-7xl mx-auto p-6">
                <div className="text-center py-8">
                    <p className="text-red-600 mb-4">{error}</p>
                    <button
                        onClick={refreshStatistics}
                        className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors flex items-center gap-2 mx-auto"
                    >
                        <IoRefreshOutline size={16} />
                        Try Again
                    </button>
                </div>
            </div>
        );
    }

    const monthOptions = [
        { value: '', label: 'All Year' },
        ...Array.from({ length: 12 }, (_, i) => ({
            value: i + 1,
            label: getMonthName(i + 1)
        }))
    ];

    const getRevenueGrowth = () => {
        if (!statistics) return null;
        const growth = statistics.revenueGrowth;
        const indicator = getGrowthIndicator(growth);

        return {
            trend: growth > 0 ? 'up' : growth < 0 ? 'down' : 'neutral',
            value: `${Math.abs(growth).toFixed(1)}%`
        };
    };

    return (
        <div className="max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex items-center justify-between mb-8">
                <div>
                    <Title level={2} className="text-3xl font-bold text-gray-900 mb-2">
                        Seller Statistics
                    </Title>
                    <p className="text-gray-600">Track your performance and revenue</p>
                </div>

                <button
                    onClick={refreshStatistics}
                    disabled={loading}
                    className="px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors flex items-center gap-2 disabled:opacity-50"
                >
                    <IoRefreshOutline size={16} className={loading ? 'animate-spin' : ''} />
                    Refresh
                </button>
            </div>

            {/* Filters */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
                <div className="flex flex-wrap gap-4 items-center">
                    {/* Year Filter */}
                    <div className="flex items-center gap-2">
                        <label className="text-sm font-medium text-gray-700">Year:</label>
                        <div className="relative">
                            <select
                                value={selectedYear}
                                onChange={(e) => setSelectedYear(parseInt(e.target.value))}
                                className="appearance-none bg-white border border-gray-300 rounded-lg px-3 py-2 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-green-500"
                            >
                                {getYearOptions().map(year => (
                                    <option key={year} value={year}>{year}</option>
                                ))}
                            </select>
                            <IoChevronDownOutline className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400" size={14} />
                        </div>
                    </div>

                    {/* Month Filter */}
                    <div className="flex items-center gap-2">
                        <label className="text-sm font-medium text-gray-700">Month:</label>
                        <div className="relative">
                            <select
                                value={selectedMonth || ''}
                                onChange={(e) => {
                                    const value = e.target.value;
                                    if (value === '' || value === null || value === undefined) {
                                        setSelectedMonth(null);
                                    } else {
                                        const monthNum = parseInt(value);
                                        if (!isNaN(monthNum) && monthNum >= 1 && monthNum <= 12) {
                                            setSelectedMonth(monthNum);
                                        } else {
                                            setSelectedMonth(null);
                                        }
                                    }
                                }}
                                className="appearance-none bg-white border border-gray-300 rounded-lg px-3 py-2 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-green-500"
                            >
                                {monthOptions.map(option => (
                                    <option key={option.value} value={option.value}>{option.label}</option>
                                ))}
                            </select>
                            <IoChevronDownOutline className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400" size={14} />
                        </div>
                    </div>

                    {/* Top Products Limit */}
                    <div className="flex items-center gap-2">
                        <label className="text-sm font-medium text-gray-700">Top Products:</label>
                        <div className="relative">
                            <select
                                value={topProductsLimit}
                                onChange={(e) => setTopProductsLimit(parseInt(e.target.value))}
                                className="appearance-none bg-white border border-gray-300 rounded-lg px-3 py-2 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-green-500"
                            >
                                <option value={5}>Top 5</option>
                                <option value={10}>Top 10</option>
                                <option value={20}>Top 20</option>
                            </select>
                            <IoChevronDownOutline className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400" size={14} />
                        </div>
                    </div>
                </div>
            </div>

            {/* Statistics Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <StatisticsCard
                    title="Total Revenue"
                    value={statistics ? formatCurrency(statistics.totalRevenue) : '$0'}
                    subtitle="All time earnings"
                    icon={IoCashOutline}
                    trend={getRevenueGrowth()?.trend}
                    trendValue={getRevenueGrowth()?.value}
                    loading={loading}
                />

                <StatisticsCard
                    title="Total Auctions"
                    value={statistics ? formatNumber(statistics.totalAuctions) : '0'}
                    subtitle="Completed auctions"
                    icon={IoStatsChartOutline}
                    loading={loading}
                />

                <StatisticsCard
                    title="Products Sold"
                    value={statistics ? formatNumber(statistics.totalSoldProducts) : '0'}
                    subtitle="Total items sold"
                    icon={IoReceiptOutline}
                    loading={loading}
                />

                <StatisticsCard
                    title="Total Orders"
                    value={statistics ? formatNumber(statistics.totalOrders) : '0'}
                    subtitle="Successful orders"
                    icon={IoTrendingUpOutline}
                    loading={loading}
                />
            </div>

            {/* Charts and Tables */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Monthly Revenue Chart */}
                <MonthlyRevenueChart
                    data={statistics?.monthlyRevenue}
                    loading={loading}
                    formatCurrency={formatCurrency}
                    getMonthName={getMonthName}
                />

                {/* Top Products Table */}
                <TopProductsTable
                    products={statistics?.topProducts}
                    loading={loading}
                    formatCurrency={formatCurrency}
                    formatNumber={formatNumber}
                />
            </div>
        </div>
    );
};

export default SellerStatistics;
