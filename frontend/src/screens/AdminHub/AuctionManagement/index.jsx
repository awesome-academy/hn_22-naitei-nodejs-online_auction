import React, { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Title } from "@/components/ui/index.js";
import { adminAuctionService } from "@/services/adminAuction.service";
import { useNotification } from "@/contexts/NotificationContext";
import AuctionManagementTable from "./components/AuctionManagementTable";
import AuctionCard from "./components/AuctionCard";
import AuctionManagementFilters from "./components/AuctionManagementFilters";
import ConfirmAuctionModal from "./components/ConfirmAuctionModal";
import Pagination from "@/components/ui/Pagination";

const AuctionManagement = () => {
    const navigate = useNavigate();
    const [auctions, setAuctions] = useState([]);
    const [filteredAuctions, setFilteredAuctions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [confirmLoading, setConfirmLoading] = useState(false);
    const [error, setError] = useState("");

    // Modal states
    const [confirmModal, setConfirmModal] = useState({ isOpen: false, auction: null });

    // Pagination state
    const [pagination, setPagination] = useState({
        page: 1,
        limit: 10,
        total: 0,
        totalPages: 0,
        hasNext: false,
        hasPrevious: false,
    });

    // Filter states
    const [searchTerm, setSearchTerm] = useState("");
    const [period, setPeriod] = useState("");
    const [searchBy, setSearchBy] = useState("title");
    const [sortBy, setSortBy] = useState("createdAt");
    const [sortOrder, setSortOrder] = useState("desc");
    const [statusFilter, setStatusFilter] = useState("");

    const { showToastNotification } = useNotification();

    // Fetch auctions from API
    const fetchAuctions = useCallback(async (page = 1, limit = 10) => {
        try {
            setLoading(true);
            setError("");

            const response = await adminAuctionService.getAuctions({
                page: page - 1, // API uses 0-based pagination
                size: limit,
                status: statusFilter || undefined,
                title: searchTerm || undefined,
                sortField: sortBy,
                sortDirection: sortOrder?.toLowerCase(),
            });

            setAuctions(response.data || []);
            setPagination({
                page: (response.page || 0) + 1, // Convert back to 1-based
                limit: response.size || 10,
                total: response.total || 0,
                totalPages: Math.ceil((response.total || 0) / (response.size || 10)),
                hasNext: ((response.page || 0) + 1) * (response.size || 10) < (response.total || 0),
                hasPrevious: (response.page || 0) > 0,
            });
        } catch (error) {
            console.error("Error fetching auctions:", error);
            setError(error.message || "Failed to fetch auctions");
            setAuctions([]);
        } finally {
            setLoading(false);
        }
    }, [searchTerm, sortBy, sortOrder, statusFilter]);

    // Initialize data
    useEffect(() => {
        fetchAuctions();
    }, [fetchAuctions]);

    // Set filtered auctions directly from server response
    useEffect(() => {
        setFilteredAuctions(auctions);
    }, [auctions]);

    // Handle pagination change
    const handlePageChange = (newPage) => {
        fetchAuctions(newPage, pagination.limit);
    };

    const handleViewDetails = (auction) => {
        navigate(`/admin-hub/auctions/${auction.auctionId}`);
    };

    const handleConfirmAuction = (auction) => {
        setConfirmModal({ isOpen: true, auction });
    };

    const handleAuctionConfirm = async () => {
        if (!confirmModal.auction) return;

        setConfirmLoading(true);
        try {
            await adminAuctionService.confirmAuction(confirmModal.auction.auctionId);

            // Update auction status locally
            setAuctions(prevAuctions =>
                prevAuctions.map(auction =>
                    auction.auctionId === confirmModal.auction.auctionId
                        ? { ...auction, status: 'READY' }
                        : auction
                )
            );

            showToastNotification('Auction confirmed successfully', 'success');
            setConfirmModal({ isOpen: false, auction: null });
        } catch (error) {
            console.error('Failed to confirm auction:', error);
            showToastNotification(error.message || 'Failed to confirm auction', 'error');
        } finally {
            setConfirmLoading(false);
        }
    };

    const handleClearFilters = () => {
        setSearchTerm("");
        setPeriod("all");
        setSearchBy("title");
        setSortBy("createdAt");
        setSortOrder("desc");
        setStatusFilter("all");
    };

    const handleSortChange = (column) => {
        if (sortBy === column) {
            setSortOrder(sortOrder === "asc" ? "desc" : "asc");
        } else {
            setSortBy(column);
            setSortOrder("desc");
        }
    };

    const formatCurrency = (amount) => {
        return new Intl.NumberFormat('vi-VN', {
            style: 'currency',
            currency: 'VND'
        }).format(amount);
    };

    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleString('vi-VN');
    };

    const getStatusColor = (status) => {
        switch (status) {
            case 'PENDING':
                return 'bg-yellow-100 text-yellow-800';
            case 'READY':
                return 'bg-blue-100 text-blue-800';
            case 'OPEN':
                return 'bg-green-100 text-green-800';
            case 'CLOSED':
                return 'bg-gray-100 text-gray-800';
            case 'CANCELED':
                return 'bg-red-100 text-red-800';
            default:
                return 'bg-gray-100 text-gray-800';
        }
    };

    if (loading && auctions.length === 0) {
        return (
            <div className="max-w-7xl mx-auto">
                <div className="flex items-center justify-center py-12">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-600"></div>
                    <span className="ml-2 text-gray-600">Loading auctions...</span>
                </div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <Title level={2} className="text-3xl font-bold text-gray-900">
                    Auction Management
                </Title>

                <div className="relative">
                    <button
                        onClick={() => fetchAuctions()}
                        className="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded-full flex items-center gap-2 transition-colors duration-200"
                    >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                        Refresh
                    </button>
                </div>
            </div>

            {/* Filters */}
            <AuctionManagementFilters
                searchTerm={searchTerm}
                setSearchTerm={setSearchTerm}
                period={period}
                setPeriod={setPeriod}
                searchBy={searchBy}
                setSearchBy={setSearchBy}
                sortBy={sortBy}
                setSortBy={setSortBy}
                sortOrder={sortOrder}
                setSortOrder={setSortOrder}
                statusFilter={statusFilter}
                setStatusFilter={setStatusFilter}
                onClearFilters={handleClearFilters}
            />

            {/* Error Message */}
            {error && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
                    <p className="text-red-800">{error}</p>
                </div>
            )}

            {/* Auctions Table - Desktop View */}
            <div className="hidden lg:block">
                <AuctionManagementTable
                    auctions={auctions}
                    loading={loading}
                    onViewDetails={handleViewDetails}
                    onConfirmAuction={handleConfirmAuction}
                    sortBy={sortBy}
                    sortOrder={sortOrder}
                    onSortChange={handleSortChange}
                    getStatusColor={getStatusColor}
                    formatCurrency={formatCurrency}
                    formatDate={formatDate}
                />
            </div>

            {/* Auctions Grid - Mobile & Tablet View */}
            <div className="lg:hidden">
                {loading ? (
                    <div className="bg-white border border-gray-200 rounded-lg p-8 text-center">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-600 mx-auto"></div>
                        <p className="mt-2 text-gray-600">Loading auctions...</p>
                    </div>
                ) : (
                    <div className="grid gap-4 sm:grid-cols-1 md:grid-cols-2">
                        {filteredAuctions.map((auction) => (
                            <AuctionCard
                                key={auction.auctionId}
                                auction={auction}
                                onViewDetails={handleViewDetails}
                                onConfirmAuction={handleConfirmAuction}
                                getStatusColor={getStatusColor}
                                formatCurrency={formatCurrency}
                                formatDate={formatDate}
                            />
                        ))}
                    </div>
                )}
            </div>

            {/* Pagination */}
            {auctions.length > 0 && (
                <Pagination
                    currentPage={pagination.page}
                    totalPages={pagination.totalPages}
                    hasNext={pagination.hasNext}
                    hasPrevious={pagination.hasPrevious}
                    onPageChange={handlePageChange}
                    totalItems={pagination.total}
                    limit={pagination.limit}
                />
            )}

            {/* Empty State */}
            {!loading && filteredAuctions.length === 0 && (
                <div className="text-center py-12">
                    <Title level={3} className="text-xl font-medium text-gray-900 mb-2">
                        No auctions found
                    </Title>
                    <p className="text-gray-600 mb-6">
                        {searchTerm ? "Try adjusting your search criteria" : "No auctions have been created yet"}
                    </p>
                </div>
            )}

            {/* Modals */}
            <ConfirmAuctionModal
                isOpen={confirmModal.isOpen}
                onClose={() => setConfirmModal({ isOpen: false, auction: null })}
                auction={confirmModal.auction}
                onConfirm={handleAuctionConfirm}
                loading={confirmLoading}
            />
        </div>
    );
};

export default AuctionManagement;
