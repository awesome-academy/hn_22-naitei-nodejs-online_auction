import React from 'react';

const StatisticsCard = ({
    title,
    value,
    subtitle,
    icon: Icon,
    trend,
    trendValue,
    className = '',
    loading = false
}) => {
    const getTrendColor = (trend) => {
        if (trend === 'up') return 'text-green-600';
        if (trend === 'down') return 'text-red-600';
        return 'text-gray-600';
    };

    const getTrendIcon = (trend) => {
        if (trend === 'up') return '↗';
        if (trend === 'down') return '↘';
        return '→';
    };

    if (loading) {
        return (
            <div className={`bg-white rounded-lg shadow-sm border border-gray-200 p-6 ${className}`}>
                <div className="animate-pulse">
                    <div className="flex items-center justify-between mb-4">
                        <div className="h-4 bg-gray-200 rounded w-1/3"></div>
                        <div className="h-8 w-8 bg-gray-200 rounded"></div>
                    </div>
                    <div className="h-8 bg-gray-200 rounded w-1/2 mb-2"></div>
                    <div className="h-3 bg-gray-200 rounded w-2/3"></div>
                </div>
            </div>
        );
    }

    return (
        <div className={`bg-white rounded-lg shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow ${className}`}>
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-medium text-gray-600">{title}</h3>
                {Icon && <Icon className="h-8 w-8 text-gray-400" />}
            </div>

            <div className="space-y-2">
                <p className="text-2xl font-bold text-gray-900">{value}</p>
                {subtitle && (
                    <p className="text-sm text-gray-500">{subtitle}</p>
                )}
                {trendValue && (
                    <div className={`flex items-center text-sm ${getTrendColor(trend)}`}>
                        <span className="mr-1">{getTrendIcon(trend)}</span>
                        <span className="font-medium">{trendValue}</span>
                        <span className="ml-1 text-gray-500">vs last month</span>
                    </div>
                )}
            </div>
        </div>
    );
};

export default StatisticsCard;
