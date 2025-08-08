import { useState, useEffect, useCallback } from 'react';
import { auctionService } from '@/services/auction.service.js';
import { useUser } from '@/contexts/UserContext.jsx';
import { useNotification } from '@/contexts/NotificationContext.jsx';

export const useAuctionListing = () => {
    const { user } = useUser();
    const { showToastNotification } = useNotification();

    const [auctions, setAuctions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchTerm, setSearchTerm] = useState("");
    const [filterPeriod, setFilterPeriod] = useState("Last 90 days");
    const [sortBy, setSortBy] = useState("Current price");

    // Fetch seller's auctions
    const fetchMyAuctions = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const response = await auctionService.getMyAuctions();
            setAuctions(response.data || []);
        } catch (err) {
            console.error('Failed to fetch auctions:', err);
            setError(err.message || 'Failed to fetch auctions');
            showToastNotification(err.message || 'Failed to fetch auctions', 'error');
        } finally {
            setLoading(false);
        }
    }, [showToastNotification]);

    // Load auctions when user is available
    useEffect(() => {
        if (user?.role === "SELLER") {
            fetchMyAuctions();
        }
    }, [user, fetchMyAuctions]);

    // Filter auctions based on search term
    const filteredAuctions = auctions.filter(auction =>
        auction.title.toLowerCase().includes(searchTerm.toLowerCase())
    );

    // Format date helper
    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            month: 'long',
            day: 'numeric',
            year: 'numeric'
        });
    };

    // Format price helper
    const formatPrice = (price) => {
        return `US ${parseFloat(price).toFixed(2)}$`;
    };

    // Action handlers
    const handleEditAuction = useCallback((auction) => {
        // Navigate to edit auction page (to be implemented)
        showToastNotification('Edit auction functionality coming soon', 'info');
    }, [showToastNotification]);

    const handleDeleteAuction = useCallback((auction) => {
        // Implement delete auction functionality
        showToastNotification('Delete auction functionality coming soon', 'info');
    }, [showToastNotification]);

    const handleReopenAuction = useCallback((auction) => {
        // Implement reopen auction functionality
        showToastNotification('Reopen auction functionality coming soon', 'info');
    }, [showToastNotification]);

    const handleCancelAuction = useCallback((auction) => {
        // Implement cancel auction functionality
        showToastNotification('Cancel auction functionality coming soon', 'info');
    }, [showToastNotification]);

    return {
        // Data
        auctions: filteredAuctions,
        loading,
        error,

        // Search and filters
        searchTerm,
        setSearchTerm,
        filterPeriod,
        setFilterPeriod,
        sortBy,
        setSortBy,

        // Helpers
        formatDate,
        formatPrice,

        // Actions
        handleEditAuction,
        handleDeleteAuction,
        handleReopenAuction,
        handleCancelAuction,
        refreshAuctions: fetchMyAuctions,
    };
};
