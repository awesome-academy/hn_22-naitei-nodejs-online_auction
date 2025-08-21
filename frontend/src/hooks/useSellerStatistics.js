import { useState, useEffect, useCallback } from 'react';
import { statisticsService } from '@/services/statistics.service.js';
import { useNotification } from '@/contexts/NotificationContext.jsx';

export const useSellerStatistics = () => {
    const { showToastNotification } = useNotification();

    const [statistics, setStatistics] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    // Filters
    const [selectedYear, setSelectedYear] = useState(new Date().getFullYear());
    const [selectedMonth, setSelectedMonth] = useState(null);
    const [topProductsLimit, setTopProductsLimit] = useState(10);

    const fetchStatistics = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);

            const params = {
                year: selectedYear,
                topProductsLimit
            };

            // Only include month if it's a valid number between 1-12
            if (selectedMonth && selectedMonth >= 1 && selectedMonth <= 12) {
                params.month = selectedMonth;
            }

            const data = await statisticsService.getSellerStatistics(params);
            setStatistics(data);
        } catch (err) {
            console.error('Failed to fetch statistics:', err);
            setError(err.message || 'Failed to fetch statistics');
            showToastNotification(err.message || 'Failed to fetch statistics', 'error');
        } finally {
            setLoading(false);
        }
    }, [selectedYear, selectedMonth, topProductsLimit, showToastNotification]);

    useEffect(() => {
        fetchStatistics();
    }, [fetchStatistics]);

    // Helper functions
    const formatCurrency = useCallback((amount) => {
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: 'USD',
            minimumFractionDigits: 2,
        }).format(amount);
    }, []);

    const formatNumber = useCallback((number) => {
        return new Intl.NumberFormat('en-US').format(number);
    }, []);

    const getMonthName = useCallback((monthNumber) => {
        const months = [
            'January', 'February', 'March', 'April', 'May', 'June',
            'July', 'August', 'September', 'October', 'November', 'December'
        ];
        return months[monthNumber - 1];
    }, []);

    const getGrowthIndicator = useCallback((growth) => {
        if (growth > 0) return { type: 'positive', icon: '↗', color: 'text-green-600' };
        if (growth < 0) return { type: 'negative', icon: '↘', color: 'text-red-600' };
        return { type: 'neutral', icon: '→', color: 'text-gray-600' };
    }, []);

    // Filter year options (last 5 years + current year)
    const getYearOptions = useCallback(() => {
        const currentYear = new Date().getFullYear();
        const years = [];
        for (let i = 0; i < 5; i++) {
            years.push(currentYear - i);
        }
        return years;
    }, []);

    return {
        // Data
        statistics,
        loading,
        error,

        // Filters
        selectedYear,
        setSelectedYear,
        selectedMonth,
        setSelectedMonth,
        topProductsLimit,
        setTopProductsLimit,

        // Actions
        refreshStatistics: fetchStatistics,

        // Helpers
        formatCurrency,
        formatNumber,
        getMonthName,
        getGrowthIndicator,
        getYearOptions,
    };
};
