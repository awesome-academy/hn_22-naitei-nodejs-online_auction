import React from 'react';

const MonthlyRevenueChart = ({ data, loading = false, formatCurrency, getMonthName }) => {
    if (loading) {
        return (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <div className="animate-pulse">
                    <div className="h-4 bg-gray-200 rounded w-1/3 mb-6"></div>
                    <div className="space-y-4">
                        {[...Array(6)].map((_, i) => (
                            <div key={i} className="flex items-center space-x-4">
                                <div className="h-3 bg-gray-200 rounded w-16"></div>
                                <div className="flex-1 h-8 bg-gray-200 rounded"></div>
                                <div className="h-3 bg-gray-200 rounded w-20"></div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        );
    }

    if (!data || data.length === 0) {
        return (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-6">Monthly Revenue</h3>
                <div className="text-center py-8">
                    <p className="text-gray-500">No revenue data available</p>
                </div>
            </div>
        );
    }

    const maxRevenue = Math.max(...data.map(item => item.revenue));

    return (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-6">Monthly Revenue</h3>

            <div className="space-y-4">
                {data.map((item) => {
                    const percentage = maxRevenue > 0 ? (item.revenue / maxRevenue) * 100 : 0;

                    return (
                        <div key={item.month} className="flex items-center space-x-4">
                            <div className="w-16 text-sm text-gray-600 font-medium">
                                {getMonthName(item.month).slice(0, 3)}
                            </div>

                            <div className="flex-1">
                                <div className="bg-gray-200 rounded-full h-8 relative overflow-hidden">
                                    <div
                                        className="bg-gradient-to-r from-green-400 to-green-600 h-full rounded-full transition-all duration-1000 ease-out"
                                        style={{ width: `${percentage}%` }}
                                    />
                                    <div className="absolute inset-0 flex items-center justify-center">
                                        <span className="text-xs font-medium text-gray-700">
                                            {item.revenue > 0 ? formatCurrency(item.revenue) : ''}
                                        </span>
                                    </div>
                                </div>
                            </div>

                            <div className="w-20 text-sm text-gray-900 font-medium text-right">
                                {formatCurrency(item.revenue)}
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

export default MonthlyRevenueChart;
