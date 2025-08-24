import React from "react";
import { IoEyeOutline, IoTimeOutline, IoPersonOutline, IoCardOutline, IoSendOutline } from "react-icons/io5";
import { getOrderProductInfo, handleImageError } from "@/utils/imageUtils.js";

const SellerOrderTable = ({
  orders,
  loading,
  onViewDetails,
  onConfirmShipped,
  sortBy,
  sortOrder,
  onSortChange,
  getStatusColor,
  formatCurrency
}) => {
  const getSortIcon = (field) => {
    if (sortBy !== field) {
      return <span className="text-gray-400">↕</span>;
    }
    return sortOrder === "asc" ? <span className="text-green-600">↑</span> : <span className="text-green-600">↓</span>;
  };

  const getProductInfo = (order) => {
    return getOrderProductInfo(order);
  };

  if (loading) {
    return (
      <div className="bg-white border border-gray-200 rounded-lg">
        <div className="p-8 text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-600 mx-auto"></div>
          <p className="mt-2 text-gray-600">Loading orders...</p>
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
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-[300px]">
                Product & Auction
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-[150px]">
                Buyer
              </th>
              <th 
                className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100 w-[120px]"
                onClick={() => onSortChange("totalAmount")}
              >
                <div className="flex items-center gap-1">
                  Amount
                  {getSortIcon("totalAmount")}
                </div>
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-[120px]">
                Status
              </th>
              <th 
                className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100 w-[140px]"
                onClick={() => onSortChange("createdAt")}
              >
                <div className="flex items-center gap-1">
                  Date
                  {getSortIcon("createdAt")}
                </div>
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-[100px]">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {orders.map((order) => {
              const productInfo = getProductInfo(order);
              
              return (
                <tr key={order.orderId} className="hover:bg-gray-50">
                  {/* Product & Auction */}
                  <td className="px-4 py-4 w-[300px]">
                    <div className="flex items-center">
                      <div className="h-10 w-10 flex-shrink-0 relative">
                        {productInfo.image ? (
                          <>
                            <img
                              className="h-10 w-10 rounded-lg object-cover"
                              src={productInfo.image}
                              alt={productInfo.name}
                              onError={(e) => handleImageError(e)}
                            />
                            <div 
                              className="absolute inset-0 h-10 w-10 rounded-lg bg-gray-200 flex items-center justify-center"
                              style={{ display: 'none' }}
                            >
                              <IoCardOutline className="text-gray-400" size={16} />
                            </div>
                          </>
                        ) : (
                          <div className="h-10 w-10 rounded-lg bg-gray-200 flex items-center justify-center">
                            <IoCardOutline className="text-gray-400" size={16} />
                          </div>
                        )}
                      </div>
                      <div className="ml-3 flex-1 min-w-0">
                        <div className="text-sm font-medium text-gray-900 truncate" title={order.auction?.title}>
                          {order.auction?.title && order.auction.title.length > 30 
                            ? order.auction.title.substring(0, 30) + "..." 
                            : order.auction?.title || "N/A"}
                        </div>
                        <div className="text-xs text-gray-500 truncate" title={productInfo.name}>
                          {productInfo.name.length > 35 
                            ? productInfo.name.substring(0, 35) + "..." 
                            : productInfo.name}
                        </div>
                      </div>
                    </div>
                  </td>
                  
                  {/* Buyer */}
                  <td className="px-4 py-4 w-[150px]">
                    <div className="flex items-center">
                      <IoPersonOutline className="text-blue-500 mr-2 flex-shrink-0" size={14} />
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium text-gray-900 truncate" title={order.user?.profile?.fullName}>
                          {order.user?.profile?.fullName && order.user.profile.fullName.length > 12
                            ? order.user.profile.fullName.substring(0, 12) + "..."
                            : order.user?.profile?.fullName || "N/A"}
                        </div>
                        <div className="text-xs text-gray-500 truncate" title={order.user?.email}>
                          {order.user?.email && order.user.email.length > 15
                            ? order.user.email.substring(0, 15) + "..."
                            : order.user?.email || ""}
                        </div>
                      </div>
                    </div>
                  </td>
                  
                  {/* Amount */}
                  <td className="px-4 py-4 whitespace-nowrap w-[120px]">
                    <div className="text-sm font-bold text-gray-900">
                      {formatCurrency(order.totalAmount)}
                    </div>
                  </td>
                  
                  {/* Status */}
                  <td className="px-4 py-4 whitespace-nowrap w-[120px]">
                    <div className="space-y-1">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(order.status)}`}>
                        {order.status}
                      </span>
                      {order.paymentDueDate && order.status === 'PENDING' && (
                        <div className="text-xs text-red-500 flex items-center gap-1">
                          <IoTimeOutline size={10} />
                          <span className="truncate">
                            {new Date(order.paymentDueDate).toLocaleDateString()}
                          </span>
                        </div>
                      )}
                    </div>
                  </td>
                  
                  {/* Date */}
                  <td className="px-4 py-4 whitespace-nowrap w-[140px]">
                    <div className="text-sm text-gray-900">
                      {new Date(order.createdAt).toLocaleDateString()}
                    </div>
                    <div className="text-xs text-gray-500">
                      {new Date(order.createdAt).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                    </div>
                  </td>
                  
                  {/* Actions */}
                  <td className="px-4 py-4 whitespace-nowrap text-sm font-medium w-[100px]">
                    <div className="flex space-x-2">
                      
                      <button
                        onClick={() => onViewDetails(order)}
                        className="text-green-600 hover:text-green-900 transition-colors duration-200 p-1 rounded hover:bg-green-50"
                        title="View Details"
                      >
                        <IoEyeOutline size={16} />
                      </button>

                      {/* Confirm Shipped Button - Only show for PAID orders */}
                      {order.status === 'PAID' && (
                        <button
                          onClick={() => onConfirmShipped(order)}
                          className="text-blue-600 hover:text-blue-900 transition-colors duration-200 p-1 rounded hover:bg-blue-50"
                          title="Confirm Shipped"
                        >
                          <IoSendOutline size={16} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      
      {/* Empty state */}
      {orders.length === 0 && (
        <div className="text-center py-12">
          <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <h3 className="mt-2 text-sm font-medium text-gray-900">No orders found</h3>
          <p className="mt-1 text-sm text-gray-500">Orders will appear here when customers purchase your auction items.</p>
        </div>
      )}
    </div>
  );
};

export default SellerOrderTable;
