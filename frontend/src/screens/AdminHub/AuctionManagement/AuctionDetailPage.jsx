import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { IoArrowBack, IoCheckmarkCircleOutline, IoTimeOutline, IoPersonOutline, IoPricetagOutline } from "react-icons/io5";
import { Title } from "@/components/ui/index.js";
import { adminAuctionService } from "@/services/adminAuction.service";
import { useNotification } from "@/contexts/NotificationContext";
import ConfirmAuctionModal from "./components/ConfirmAuctionModal";
import "./styles/auctionDetail.css";

const AuctionDetailPage = () => {
    const { auctionId } = useParams();
    const navigate = useNavigate();
    const { showToastNotification } = useNotification();

    const [auction, setAuction] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [confirmModal, setConfirmModal] = useState({ isOpen: false });
    const [confirmLoading, setConfirmLoading] = useState(false);

    useEffect(() => {
        if (auctionId) {
            fetchAuctionDetails();
        }
    }, [auctionId]);

    const fetchAuctionDetails = async () => {
        try {
            setLoading(true);
            setError("");
            const details = await adminAuctionService.getAuctionById(auctionId);
            setAuction(details);
        } catch (err) {
            setError(err.message || "Failed to load auction details");
        } finally {
            setLoading(false);
        }
    };

    const handleConfirmAuction = () => {
        setConfirmModal({ isOpen: true });
    };

    const handleAuctionConfirm = async () => {
        if (!auction) return;

        setConfirmLoading(true);
        try {
            await adminAuctionService.confirmAuction(auction.auctionId);

            // Update auction status locally
            setAuction(prev => ({ ...prev, status: 'READY' }));

            showToastNotification('Auction confirmed successfully', 'success');
            setConfirmModal({ isOpen: false });
        } catch (error) {
            console.error('Failed to confirm auction:', error);
            showToastNotification(error.message || 'Failed to confirm auction', 'error');
        } finally {
            setConfirmLoading(false);
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
                return 'bg-yellow-100 text-yellow-800 border-yellow-200';
            case 'READY':
                return 'bg-blue-100 text-blue-800 border-blue-200';
            case 'OPEN':
                return 'bg-green-100 text-green-800 border-green-200';
            case 'CLOSED':
                return 'bg-gray-100 text-gray-800 border-gray-200';
            case 'CANCELED':
                return 'bg-red-100 text-red-800 border-red-200';
            default:
                return 'bg-gray-100 text-gray-800 border-gray-200';
        }
    };

    const canConfirmAuction = (auction) => {
        return auction?.status === 'PENDING';
    };

    if (loading) {
        return (
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                <div className="flex items-center justify-center py-12">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-600"></div>
                    <span className="ml-2 text-gray-600">Loading auction details...</span>
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                    <p className="text-red-800">{error}</p>
                    <button
                        onClick={() => navigate('/admin-hub/auctions')}
                        className="mt-4 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
                    >
                        Back to Auctions
                    </button>
                </div>
            </div>
        );
    }

    if (!auction) {
        return (
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                <div className="text-center py-12">
                    <p className="text-gray-600">Auction not found</p>
                    <button
                        onClick={() => navigate('/admin-hub/auctions')}
                        className="mt-4 px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors"
                    >
                        Back to Auctions
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            {/* Header */}
            <div className="pageHeader">
                <div className="headerTitle">
                    <button
                        onClick={() => navigate('/admin-hub/auctions')}
                        className="backButton"
                    >
                        <IoArrowBack size={24} className="text-gray-600" />
                    </button>
                    <div>
                        <Title level={2} className="text-2xl font-bold text-gray-900">
                            {auction.title}
                        </Title>
                        <p className="text-sm text-gray-600">ID: {auction.auctionId}</p>
                    </div>
                </div>

                <div className="headerActions">
                    <span className={`statusBadge ${getStatusColor(auction.status)}`}>
                        {auction.status}
                    </span>
                    {canConfirmAuction(auction) && (
                        <button
                            onClick={handleConfirmAuction}
                            style={{
                                backgroundColor: '#16a34a',
                                color: 'white',
                                padding: '0.75rem 1.5rem',
                                borderRadius: '0.5rem',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.5rem',
                                fontWeight: '500',
                                boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
                                border: '1px solid #15803d',
                                minWidth: '160px',
                                position: 'relative',
                                zIndex: '50'
                            }}
                        >
                            <IoCheckmarkCircleOutline size={18} style={{ color: 'white' }} />
                            <span style={{ color: 'white', fontWeight: '500' }}>Confirm Auction</span>
                        </button>
                    )}
                </div>
            </div>

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Left Column - Main Info */}
                <div className="lg:col-span-2 space-y-6">
                    {/* Basic Information Card */}
                    <div className="bg-white rounded-lg border border-gray-200 p-6">
                        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                            <IoTimeOutline className="text-gray-600" />
                            Auction Information
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Start Time</label>
                                <p className="text-sm text-gray-900 bg-gray-50 px-3 py-2 rounded-md">
                                    {formatDate(auction.startTime)}
                                </p>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">End Time</label>
                                <p className="text-sm text-gray-900 bg-gray-50 px-3 py-2 rounded-md">
                                    {formatDate(auction.endTime)}
                                </p>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Created At</label>
                                <p className="text-sm text-gray-900 bg-gray-50 px-3 py-2 rounded-md">
                                    {formatDate(auction.createdAt)}
                                </p>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Last Bid Time</label>
                                <p className="text-sm text-gray-900 bg-gray-50 px-3 py-2 rounded-md">
                                    {auction.lastBidTime ? formatDate(auction.lastBidTime) : 'No bids yet'}
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Products Card */}
                    {auction.products && auction.products.length > 0 && (
                        <div className="bg-white rounded-lg border border-gray-200 p-6">
                            <h3 className="text-lg font-semibold text-gray-900 mb-4">
                                Products ({auction.products.length} items)
                            </h3>
                            <div className="space-y-4">
                                {auction.products.map((product) => (
                                    <div key={product.productId} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50 transition-colors">
                                        <div className="flex items-start space-x-4">
                                            {product.images && product.images.length > 0 && (
                                                <img
                                                    src={product.images[0]}
                                                    alt={product.name}
                                                    className="w-20 h-20 object-cover rounded-lg border border-gray-200"
                                                />
                                            )}
                                            <div className="flex-1">
                                                <h4 className="font-medium text-gray-900 text-lg mb-1">
                                                    {product.name}
                                                </h4>
                                                <p className="text-sm text-gray-600 mb-2">
                                                    {product.description}
                                                </p>
                                                <div className="flex items-center justify-between">
                                                    <span className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-blue-100 text-blue-800">
                                                        Quantity: {product.quantity}
                                                    </span>
                                                    {product.categories && product.categories.length > 0 && (
                                                        <div className="flex gap-1">
                                                            {product.categories.map((category, index) => (
                                                                <span key={index} className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-gray-100 text-gray-800">
                                                                    {category}
                                                                </span>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>

                {/* Right Column - Sidebar Info */}
                <div className="space-y-6">
                    {/* Seller Information Card */}
                    <div className="bg-white rounded-lg border border-gray-200 p-6">
                        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                            <IoPersonOutline className="text-gray-600" />
                            Seller Information
                        </h3>
                        <div className="space-y-3">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
                                <p className="text-sm text-gray-900">{auction.sellerName || 'Not provided'}</p>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Seller ID</label>
                                <p className="text-sm text-gray-900 font-mono">{auction.sellerId}</p>
                            </div>
                        </div>
                    </div>

                    {/* Pricing Information Card */}
                    <div className="bg-white rounded-lg border border-gray-200 p-6">
                        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                            <IoPricetagOutline className="text-gray-600" />
                            Pricing Information
                        </h3>
                        <div className="space-y-4">
                            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                                <label className="block text-sm font-medium text-green-700 mb-1">Starting Price</label>
                                <p className="text-lg font-bold text-green-900">
                                    {formatCurrency(auction.startingPrice)}
                                </p>
                            </div>
                            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                                <label className="block text-sm font-medium text-blue-700 mb-1">Current Price</label>
                                <p className="text-lg font-bold text-blue-900">
                                    {formatCurrency(auction.currentPrice)}
                                </p>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Minimum Bid Increment</label>
                                <p className="text-sm text-gray-900">
                                    {formatCurrency(auction.minimumBidIncrement)}
                                </p>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Total Bids</label>
                                <p className="text-sm text-gray-900">
                                    {auction.bids ? auction.bids.length : 0} bids
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Bidding History */}
                    {auction.bids && auction.bids.length > 0 && (
                        <div className="bg-white rounded-lg border border-gray-200 p-6">
                            <h3 className="text-lg font-semibold text-gray-900 mb-4">
                                Bidding History
                            </h3>
                            <div className="space-y-2 max-h-64 overflow-y-auto">
                                {auction.bids.slice(0, 10).map((bid, index) => (
                                    <div key={index} className="flex justify-between items-center py-2 border-b border-gray-100 last:border-b-0">
                                        <span className="text-sm text-gray-600">Bid #{index + 1}</span>
                                        <span className="text-sm font-medium text-gray-900">
                                            {formatCurrency(bid.amount || 0)}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Confirm Modal */}
            <ConfirmAuctionModal
                isOpen={confirmModal.isOpen}
                onClose={() => setConfirmModal({ isOpen: false })}
                auction={auction}
                onConfirm={handleAuctionConfirm}
                loading={confirmLoading}
            />
        </div>
    );
};

export default AuctionDetailPage;
