import React from "react";
import './auctionButtons.css';

const AuctionManagementTable = ({
    auctions,
    loading,
    onViewDetails,
    onConfirmAuction,
    sortBy,
    sortOrder,
    onSortChange,
    getStatusColor,
    formatCurrency,
    formatDate,
}) => {
    const getSortIcon = (column) => {
        if (sortBy !== column) {
            return (
                <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
                </svg>
            );
        }

        return sortOrder === "asc" ? (
            <svg className="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
            </svg>
        ) : (
            <svg className="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
        );
    };

    const getSortableHeaderClass = (column) => {
        return `px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-50 select-none ${sortBy === column ? "bg-gray-50" : ""
            }`;
    };

    const canConfirmAuction = (auction) => {
        return auction.status === 'PENDING';
    };

    if (loading) {
        return (
            <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
                <div className="p-8 text-center">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-600 mx-auto"></div>
                    <p className="mt-2 text-gray-600">Loading auctions...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                        <tr>
                            <th
                                className={getSortableHeaderClass("title")}
                                onClick={() => onSortChange("title")}
                            >
                                <div className="flex items-center space-x-1">
                                    <span>Title</span>
                                    {getSortIcon("title")}
                                </div>
                            </th>
                            <th
                                className={getSortableHeaderClass("seller")}
                                onClick={() => onSortChange("seller")}
                            >
                                <div className="flex items-center space-x-1">
                                    <span>Seller</span>
                                    {getSortIcon("seller")}
                                </div>
                            </th>
                            <th
                                className={getSortableHeaderClass("startingPrice")}
                                onClick={() => onSortChange("startingPrice")}
                            >
                                <div className="flex items-center space-x-1">
                                    <span>Current Price</span>
                                    {getSortIcon("startingPrice")}
                                </div>
                            </th>
                            <th
                                className={getSortableHeaderClass("startTime")}
                                onClick={() => onSortChange("startTime")}
                            >
                                <div className="flex items-center space-x-1">
                                    <span>Start Time</span>
                                    {getSortIcon("startTime")}
                                </div>
                            </th>
                            <th
                                className={getSortableHeaderClass("endTime")}
                                onClick={() => onSortChange("endTime")}
                            >
                                <div className="flex items-center space-x-1">
                                    <span>End Time</span>
                                    {getSortIcon("endTime")}
                                </div>
                            </th>
                            <th
                                className={getSortableHeaderClass("status")}
                                onClick={() => onSortChange("status")}
                            >
                                <div className="flex items-center space-x-1">
                                    <span>Status</span>
                                    {getSortIcon("status")}
                                </div>
                            </th>
                            <th
                                className={getSortableHeaderClass("createdAt")}
                                onClick={() => onSortChange("createdAt")}
                            >
                                <div className="flex items-center space-x-1">
                                    <span>Created</span>
                                    {getSortIcon("createdAt")}
                                </div>
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Actions
                            </th>
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {auctions.map((auction) => (
                            <tr key={auction.auctionId} className="hover:bg-gray-50">
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="text-sm font-medium text-gray-900 max-w-xs truncate">
                                        {auction.title}
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="text-sm text-gray-900">
                                        {auction.sellerName || auction.sellerEmail || 'Unknown'}
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="text-sm text-gray-900">
                                        {formatCurrency(auction.currentPrice || auction.startingPrice)}
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="text-sm text-gray-900">
                                        {formatDate(auction.startTime)}
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="text-sm text-gray-900">
                                        {formatDate(auction.endTime)}
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(auction.status)}`}>
                                        {auction.status}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="text-sm text-gray-900">
                                        Not available
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
                                    <button
                                        onClick={() => onViewDetails(auction)}
                                        className="text-blue-600 hover:text-blue-900 transition-colors"
                                    >
                                        View Details
                                    </button>
                                    {canConfirmAuction(auction) && (
                                        <button
                                            onClick={() => onConfirmAuction(auction)}
                                            className="tableConfirmButton"
                                        >
                                            <span className="auctionConfirmText">Confirm</span>
                                        </button>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {auctions.length === 0 && (
                <div className="p-8 text-center">
                    <p className="text-gray-500">No auctions found</p>
                </div>
            )}
        </div>
    );
};

export default AuctionManagementTable;
