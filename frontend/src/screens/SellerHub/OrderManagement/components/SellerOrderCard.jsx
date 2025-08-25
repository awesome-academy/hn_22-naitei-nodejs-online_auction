import React from "react";
import { IoEyeOutline, IoTimeOutline, IoPersonOutline, IoCardOutline } from "react-icons/io5";
import { getOrderProductInfo, handleImageError } from "@/utils/imageUtils.js";

const SellerOrderCard = ({
  order,
  onViewDetails,
  getStatusColor,
  formatCurrency
}) => {
  const productInfo = getOrderProductInfo(order);

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow duration-200">
      {/* Order ID & Date */}
      <div className="flex justify-between items-start mb-3">
        <div>
          <div className="text-sm font-medium text-gray-900">
            Order #{order.orderId.slice(-8)}
          </div>
          <div className="text-xs text-gray-500">
            {new Date(order.createdAt).toLocaleDateString()}
          </div>
        </div>
        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(order.status)}`}>
          {order.status}
        </span>
      </div>

      {/* Product Info */}
      <div className="flex items-start gap-3 mb-3">
        <div className="w-12 h-12 flex-shrink-0 relative">
          {productInfo.image ? (
            <>
              <img
                className="w-12 h-12 rounded-lg object-cover"
                src={productInfo.image}
                alt={productInfo.name}
                onError={(e) => handleImageError(e)}
              />
              <div 
                className="absolute inset-0 w-12 h-12 rounded-lg bg-gray-200 flex items-center justify-center"
                style={{ display: 'none' }}
              >
                <IoCardOutline className="text-gray-400" size={20} />
              </div>
            </>
          ) : (
            <div className="w-12 h-12 rounded-lg bg-gray-200 flex items-center justify-center">
              <IoCardOutline className="text-gray-400" size={20} />
            </div>
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-gray-900 line-clamp-1" title={order.auction?.title}>
            {order.auction?.title || "N/A"}
          </div>
          <div className="text-xs text-gray-500 line-clamp-1" title={productInfo.name}>
            {productInfo.name}
          </div>
        </div>
      </div>

      {/* Amount */}
      <div className="mb-3">
        <div className="text-lg font-bold text-gray-900">
          {formatCurrency(order.totalAmount)}
        </div>
      </div>

      {/* Buyer Info */}
      <div className="bg-blue-50 rounded-lg p-3 mb-3">
        <div className="flex items-center text-sm">
          <IoPersonOutline className="text-blue-500 mr-2" size={16} />
          <span className="text-blue-700 font-medium">Buyer</span>
        </div>
        <div className="mt-1 ml-6">
          <div className="font-medium text-gray-900 truncate" title={order.user?.profile?.fullName}>
            {order.user?.profile?.fullName || "N/A"}
          </div>
          <div className="text-xs text-gray-600 truncate" title={order.user?.email}>
            {order.user?.email || ""}
          </div>
        </div>
      </div>

      {/* Payment Due Date */}
      {order.paymentDueDate && order.status === 'PENDING' && (
        <div className="mb-3 p-2 bg-red-50 rounded text-xs text-red-600 flex items-center gap-1">
          <IoTimeOutline size={12} />
          <span>Due: {new Date(order.paymentDueDate).toLocaleDateString()}</span>
        </div>
      )}

      {/* Actions */}
      <div className="flex justify-end pt-2 border-t border-gray-100">
        <button
          onClick={() => onViewDetails(order)}
          className="text-green-600 hover:text-green-900 transition-colors duration-200 p-2"
          title="View Details"
        >
          <IoEyeOutline size={16} />
        </button>
      </div>
    </div>
  );
};

export default SellerOrderCard;
