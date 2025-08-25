import React from "react";

const AuctionCard = ({
    auction,
    onViewDetails,
    onConfirmAuction,
    getStatusColor,
    formatCurrency,
    formatDate,
}) => {
    const canConfirmAuction = (auction) => {
        return auction.status === 'PENDING';
    };

    return (
        <div className="bg-white border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
            {/* Header */}
            <div className="flex justify-between items-start mb-4">
                <div className="flex-1">
                    <h3 className="text-lg font-semibold text-gray-900 mb-1 truncate">
                        {auction.title}
                    </h3>
                    <p className="text-sm text-gray-600">
                        ID: {auction.auctionId}
                    </p>
                </div>
                <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(auction.status)}`}>
                    {auction.status}
                </span>
            </div>

            {/* Seller Info */}
            <div className="mb-4">
                <p className="text-sm text-gray-600">
                    <span className="font-medium">Seller:</span> {auction.sellerName || auction.sellerEmail || 'Unknown'}
                </p>
            </div>

            {/* Price and Time */}
            <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                    <p className="text-xs text-gray-500 mb-1">Starting Price</p>
                    <p className="text-sm font-semibold text-gray-900">
                        {formatCurrency(auction.startingPrice)}
                    </p>
                </div>
                <div>
                    <p className="text-xs text-gray-500 mb-1">Current Price</p>
                    <p className="text-sm font-semibold text-gray-900">
                        {formatCurrency(auction.currentPrice || auction.startingPrice)}
                    </p>
                </div>
            </div>

            {/* Time Information */}
            <div className="space-y-2 mb-4">
                <div>
                    <p className="text-xs text-gray-500">Start Time</p>
                    <p className="text-sm text-gray-900">{formatDate(auction.startTime)}</p>
                </div>
                <div>
                    <p className="text-xs text-gray-500">End Time</p>
                    <p className="text-sm text-gray-900">{formatDate(auction.endTime)}</p>
                </div>
            </div>

            {/* Products Info - Remove since not available in basic response */}

            {/* Actions */}
            <div className="flex space-x-2">
                <button
                    onClick={() => onViewDetails(auction)}
                    className="flex-1 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 transition-colors"
                >
                    View Details
                </button>
                {canConfirmAuction(auction) && (
                    <button
                        onClick={() => onConfirmAuction(auction)}
                        className="flex-1 px-4 py-2 bg-green-600 text-white text-sm font-medium rounded-md hover:bg-green-700 transition-colors"
                    >
                        Confirm
                    </button>
                )}
            </div>
        </div>
    );
};

export default AuctionCard;
