import React, { useState, useEffect } from "react";
import { IoCloseOutline } from "react-icons/io5";
import { adminAuctionService } from "@/services/adminAuction.service";

const AuctionDetailsModal = ({
    isOpen,
    onClose,
    auction,
    getStatusColor,
    formatCurrency,
    formatDate,
}) => {
    const [auctionDetails, setAuctionDetails] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    useEffect(() => {
        if (isOpen && auction?.auctionId) {
            fetchAuctionDetails();
        }
    }, [isOpen, auction?.auctionId]);

    const fetchAuctionDetails = async () => {
        try {
            setLoading(true);
            setError("");
            const details = await adminAuctionService.getAuctionById(auction.auctionId);
            setAuctionDetails(details);
        } catch (err) {
            setError(err.message || "Failed to load auction details");
        } finally {
            setLoading(false);
        }
    };

    if (!isOpen || !auction) return null;

    const displayAuction = auctionDetails || auction;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
            <div className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b border-gray-200">
                    <h2 className="text-xl font-semibold text-gray-900">
                        Auction Details
                    </h2>
                    <button
                        onClick={onClose}
                        className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                    >
                        <IoCloseOutline size={24} className="text-gray-500" />
                    </button>
                </div>

                {/* Content */}
                <div className="p-6">
                    {/* Loading State */}
                    {loading && (
                        <div className="flex items-center justify-center py-8">
                            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-600"></div>
                            <span className="ml-2 text-gray-600">Loading details...</span>
                        </div>
                    )}

                    {/* Error State */}
                    {error && (
                        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
                            <p className="text-red-800">{error}</p>
                        </div>
                    )}

                    {/* Content - only show when not loading and no error */}
                    {!loading && !error && (
                        <>
                            {/* Basic Information */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                                <div className="space-y-4">
                                    <div>
                                        <h3 className="text-lg font-semibold text-gray-900 mb-4">Basic Information</h3>
                                        <div className="space-y-3">
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700">Title</label>
                                                <p className="text-sm text-gray-900">{displayAuction.title}</p>
                                            </div>
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700">Auction ID</label>
                                                <p className="text-sm text-gray-900">{displayAuction.auctionId}</p>
                                            </div>
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700">Status</label>
                                                <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(displayAuction.status)}`}>
                                                    {displayAuction.status}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div className="space-y-4">
                                    <div>
                                        <h3 className="text-lg font-semibold text-gray-900 mb-4">Seller Information</h3>
                                        <div className="space-y-3">
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700">Name</label>
                                                <p className="text-sm text-gray-900">
                                                    {displayAuction.seller?.profile?.fullName || 'Not provided'}
                                                </p>
                                            </div>
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700">Email</label>
                                                <p className="text-sm text-gray-900">{displayAuction.seller?.email || 'Unknown'}</p>
                                            </div>
                                            <div>
                                                <label className="block text-sm font-medium text-gray-700">Phone</label>
                                                <p className="text-sm text-gray-900">
                                                    {displayAuction.seller?.profile?.phoneNumber || 'Not provided'}
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Pricing and Timing */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                                <div>
                                    <h3 className="text-lg font-semibold text-gray-900 mb-4">Pricing Information</h3>
                                    <div className="space-y-3">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700">Starting Price</label>
                                            <p className="text-sm text-gray-900">{formatCurrency(displayAuction.startingPrice)}</p>
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700">Minimum Bid Increment</label>
                                            <p className="text-sm text-gray-900">{formatCurrency(displayAuction.minimumBidIncrement || 0)}</p>
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700">Current Price</label>
                                            <p className="text-sm text-gray-900">
                                                {formatCurrency(displayAuction.currentPrice || displayAuction.startingPrice)}
                                            </p>
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700">Total Bids</label>
                                            <p className="text-sm text-gray-900">{displayAuction.bidCount || 0} bids</p>
                                        </div>
                                    </div>
                                </div>

                                <div>
                                    <h3 className="text-lg font-semibold text-gray-900 mb-4">Timing Information</h3>
                                    <div className="space-y-3">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700">Start Time</label>
                                            <p className="text-sm text-gray-900">{formatDate(displayAuction.startTime)}</p>
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700">End Time</label>
                                            <p className="text-sm text-gray-900">{formatDate(displayAuction.endTime)}</p>
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700">Created At</label>
                                            <p className="text-sm text-gray-900">{displayAuction.createdAt ? formatDate(displayAuction.createdAt) : 'Not available'}</p>
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700">Last Bid Time</label>
                                            <p className="text-sm text-gray-900">
                                                {displayAuction.lastBidTime ? formatDate(displayAuction.lastBidTime) : 'No bids yet'}
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Products */}
                            {displayAuction.auctionProducts && displayAuction.auctionProducts.length > 0 && (
                                <div className="mb-6">
                                    <h3 className="text-lg font-semibold text-gray-900 mb-4">Products</h3>
                                    <div className="grid gap-4">
                                        {displayAuction.auctionProducts.map((item) => (
                                            <div key={item.productId} className="border border-gray-200 rounded-lg p-4">
                                                <div className="flex items-start space-x-4">
                                                    {item.product?.images?.[0]?.imageUrl && (
                                                        <img
                                                            src={item.product.images[0].imageUrl}
                                                            alt={item.product.name}
                                                            className="w-16 h-16 object-cover rounded-lg"
                                                        />
                                                    )}
                                                    <div className="flex-1">
                                                        <h4 className="font-medium text-gray-900">
                                                            {item.product?.name || 'Unknown Product'}
                                                        </h4>
                                                        <p className="text-sm text-gray-600 mt-1">
                                                            {item.product?.description || 'No description'}
                                                        </p>
                                                        <div className="flex justify-between items-center mt-2">
                                                            <span className="text-sm text-gray-500">
                                                                Quantity: {item.quantity}
                                                            </span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Cancel Reason (if applicable) */}
                            {displayAuction.status === 'CANCELED' && displayAuction.cancelReason && (
                                <div className="mb-6">
                                    <h3 className="text-lg font-semibold text-gray-900 mb-4">Cancel Reason</h3>
                                    <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                                        <p className="text-sm text-red-800">{displayAuction.cancelReason}</p>
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                </div>

                {/* Footer */}
                <div className="flex justify-end p-6 border-t border-gray-200">
                    <button
                        onClick={onClose}
                        className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors"
                    >
                        Close
                    </button>
                </div>
            </div>
        </div>
    );
};

export default AuctionDetailsModal;
