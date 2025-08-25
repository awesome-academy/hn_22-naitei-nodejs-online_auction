import React from "react";
import { IoEyeOutline, IoCloseCircleOutline, IoTimeOutline, IoPersonOutline, IoCardOutline } from "react-icons/io5";
import { getPrimaryImageUrl, handleImageError } from "@/utils/imageUtils";

const OrderCard = ({
  order,
  onViewDetails,
  onCancelOrder,
  getStatusColor,
  formatCurrency
}) => {
  const getProductInfo = (order) => {
    // Handle direct product reference (order.auction.product)
    if (order.auction?.product) {
      const product = order.auction.product;
      const primaryImage = getPrimaryImageUrl(product.images);
      
      return {
        name: product.name || "N/A",
        image: primaryImage
      };
    }
    
    // Handle auctionProducts array structure (order.auction.auctionProducts)
    if (order.auction?.auctionProducts && order.auction.auctionProducts.length > 0) {
      const product = order.auction.auctionProducts[0].product;
      const primaryImage = getPrimaryImageUrl(product.images);
      
      return {
        name: product.name || "N/A",
        image: primaryImage
      };
    }
    
    return { name: "N/A", image: null };
  };

  const productInfo = getProductInfo(order);

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow duration-200">
      <div className="flex justify-between items-start mb-3">
        <div>
          <h3 className="text-sm font-medium text-gray-900 line-clamp-1">
            {order.auction?.title || "N/A"}
          </h3>
          <p className="text-xs text-gray-500">
            {new Date(order.createdAt).toLocaleDateString()} {new Date(order.createdAt).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
          </p>
        </div>
        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(order.status)}`}>
          {order.status}
        </span>
      </div>

      {/* Product Info */}
      <div className="flex items-center mb-3">
        <div className="h-12 w-12 flex-shrink-0">
          {productInfo.image ? (
            <img
              className="h-12 w-12 rounded-lg object-cover"
              src={productInfo.image}
              alt={productInfo.name}
              onError={handleImageError}
            />
          ) : (
            <div className="h-12 w-12 rounded-lg bg-gray-200 flex items-center justify-center">
              <IoCardOutline className="text-gray-400" size={20} />
            </div>
          )}
        </div>
        <div className="ml-3 flex-1 min-w-0">
          <div className="text-sm font-medium text-gray-900 line-clamp-1" title={productInfo.name}>
            {productInfo.name}
          </div>
          <div className="text-xs text-gray-500">
            Product from auction
          </div>
        </div>
      </div>

      {/* Amount */}
      <div className="mb-3">
        <div className="text-lg font-bold text-gray-900">
          {formatCurrency(order.totalAmount)}
        </div>
      </div>

      {/* Buyer & Seller */}
      <div className="grid grid-cols-1 gap-3 mb-3">
        <div className="bg-blue-50 rounded-lg p-3">
          <div className="flex items-center text-sm">
            <IoPersonOutline className="text-blue-500 mr-2" size={16} />
            <span className="text-blue-700 font-medium">Buyer</span>
          </div>
          <div className="mt-1 ml-6">
            <div className="font-medium text-gray-900 line-clamp-1" title={order.user?.profile?.fullName}>
              {order.user?.profile?.fullName || "N/A"}
            </div>
            <div className="text-xs text-gray-600 line-clamp-1" title={order.user?.email}>
              {order.user?.email || ""}
            </div>
          </div>
        </div>
        
        <div className="bg-green-50 rounded-lg p-3">
          <div className="flex items-center text-sm">
            <IoPersonOutline className="text-green-500 mr-2" size={16} />
            <span className="text-green-700 font-medium">Seller</span>
          </div>
          <div className="mt-1 ml-6">
            <div className="font-medium text-gray-900 line-clamp-1" title={order.auction?.seller?.profile?.fullName}>
              {order.auction?.seller?.profile?.fullName || "N/A"}
            </div>
            <div className="text-xs text-gray-600 line-clamp-1" title={order.auction?.seller?.email}>
              {order.auction?.seller?.email || ""}
            </div>
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
      <div className="flex justify-end space-x-2 pt-2 border-t border-gray-100">
        <button
          onClick={() => onViewDetails(order)}
          className="text-green-600 hover:text-green-900 transition-colors duration-200 p-2"
          title="View Details"
        >
          <IoEyeOutline size={16} />
        </button>
        
        {order.status !== 'COMPLETED' && order.status !== 'CANCELED' && (
          <button
            onClick={() => onCancelOrder(order)}
            className="text-red-600 hover:text-red-900 transition-colors duration-200 p-2"
            title="Cancel Order"
          >
            <IoCloseCircleOutline size={16} />
          </button>
        )}
      </div>
    </div>
  );
};

export default OrderCard;
