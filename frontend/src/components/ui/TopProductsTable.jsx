import React from 'react';
import { IoImageOutline, IoTrophyOutline } from 'react-icons/io5';

const TopProductsTable = ({ products, loading = false, formatCurrency, formatNumber }) => {
    if (loading) {
        return (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <div className="animate-pulse">
                    <div className="h-4 bg-gray-200 rounded w-1/3 mb-6"></div>
                    <div className="space-y-4">
                        {[...Array(5)].map((_, i) => (
                            <div key={i} className="flex items-center space-x-4">
                                <div className="h-12 w-12 bg-gray-200 rounded"></div>
                                <div className="flex-1 space-y-2">
                                    <div className="h-4 bg-gray-200 rounded w-2/3"></div>
                                    <div className="h-3 bg-gray-200 rounded w-1/3"></div>
                                </div>
                                <div className="h-4 bg-gray-200 rounded w-16"></div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        );
    }

    if (!products || products.length === 0) {
        return (
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-6">Top Products by Auction Participation</h3>
                <div className="text-center py-8">
                    <IoTrophyOutline className="w-12 h-12 text-gray-300 mx-auto mb-4" />
                    <p className="text-gray-500">No product data available</p>
                </div>
            </div>
        );
    }

    return (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-6">Top Products by Auction Participation</h3>

            <div className="space-y-4">
                {products.map((product, index) => (
                    <div key={product.productId} className="flex items-center space-x-4 p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors">
                        {/* Rank */}
                        <div className="flex-shrink-0">
                            {index < 3 ? (
                                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-white font-bold text-sm ${index === 0 ? 'bg-yellow-500' :
                                        index === 1 ? 'bg-gray-400' :
                                            'bg-amber-600'
                                    }`}>
                                    {index + 1}
                                </div>
                            ) : (
                                <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center text-gray-600 font-bold text-sm">
                                    {index + 1}
                                </div>
                            )}
                        </div>

                        {/* Product Image */}
                        <div className="flex-shrink-0">
                            <div className="w-12 h-12 rounded-lg overflow-hidden bg-gray-100 border border-gray-200">
                                {product.imageUrl ? (
                                    <img
                                        src={product.imageUrl}
                                        alt={product.productName}
                                        className="w-full h-full object-cover"
                                        onError={(e) => {
                                            e.target.style.display = 'none';
                                            e.target.nextSibling.style.display = 'flex';
                                        }}
                                    />
                                ) : null}
                                <div className="w-full h-full flex items-center justify-center text-gray-400" style={{ display: product.imageUrl ? 'none' : 'flex' }}>
                                    <IoImageOutline className="w-6 h-6" />
                                </div>
                            </div>
                        </div>

                        {/* Product Info */}
                        <div className="flex-1 min-w-0">
                            <h4 className="text-sm font-medium text-gray-900 truncate mb-1">
                                {product.productName}
                            </h4>
                            <div className="flex items-center space-x-4 text-xs text-gray-500">
                                <span>{formatNumber(product.totalAuctions)} auctions</span>
                                <span>•</span>
                                <span>{formatNumber(product.totalBids)} bids</span>
                                <span>•</span>
                                <span>{formatCurrency(product.totalRevenue)} revenue</span>
                            </div>
                        </div>

                        {/* Bid Count (main metric) */}
                        <div className="flex-shrink-0 text-right">
                            <div className="text-lg font-bold text-gray-900">
                                {formatNumber(product.totalBids)}
                            </div>
                            <div className="text-xs text-gray-500">
                                total bids
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default TopProductsTable;
