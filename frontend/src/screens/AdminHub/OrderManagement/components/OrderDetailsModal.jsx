import React from "react";
import { IoCloseOutline, IoReceiptOutline, IoPerson, IoStorefront, IoCalendarOutline, IoCardOutline } from "react-icons/io5";
import { getPrimaryImageUrl, handleImageError } from "@/utils/imageUtils";

const OrderDetailsModal = ({ 
  isOpen, 
  onClose, 
  order, 
  getStatusColor, 
  formatCurrency, 
  formatDate 
}) => {
  if (!isOpen || !order) return null;

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
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[85vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <IoReceiptOutline className="text-green-600" size={20} />
            <div>
              <h2 className="text-lg font-bold text-gray-900">Order Details</h2>
              <p className="text-xs text-gray-600">#{order.orderId}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors duration-200"
          >
            <IoCloseOutline size={20} />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4">
          {/* Order Summary */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Order Info */}
            <div className="bg-gray-50 rounded-lg p-3">
              <h3 className="text-base font-semibold text-gray-900 mb-3 flex items-center gap-2">
                <IoReceiptOutline size={16} />
                Order Information
              </h3>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Order ID:</span>
                  <span className="text-sm font-medium">#{order.orderId.slice(-8)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Status:</span>
                  <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(order.status)}`}>
                    {order.status}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Total Amount:</span>
                  <span className="text-sm font-bold text-green-600">{formatCurrency(order.totalAmount)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Created:</span>
                  <span className="text-sm font-medium">{formatDate(order.createdAt)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Last Updated:</span>
                  <span className="text-sm font-medium">{formatDate(order.updatedAt)}</span>
                </div>
                {order.paymentDueDate && (
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Payment Due:</span>
                    <span className="text-sm font-medium text-red-600">{formatDate(order.paymentDueDate)}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Auction Info */}
            <div className="bg-gray-50 rounded-lg p-3">
              <h3 className="text-base font-semibold text-gray-900 mb-3 flex items-center gap-2">
                <IoCardOutline size={16} />
                Auction Information
              </h3>
              {order.auction ? (
                <div className="space-y-2">
                  <div>
                    <span className="text-sm text-gray-600 block">Auction Title:</span>
                    <span className="text-sm font-medium">{order.auction.title}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Starting Price:</span>
                    <span className="text-sm font-medium">{formatCurrency(order.auction.startingPrice)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Winning Bid:</span>
                    <span className="text-sm font-medium text-green-600">{formatCurrency(order.auction.winningBid)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Start Date:</span>
                    <span className="text-sm font-medium">{formatDate(order.auction.startDate)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">End Date:</span>
                    <span className="text-sm font-medium">{formatDate(order.auction.endDate)}</span>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-gray-500">No auction information available</p>
              )}
            </div>
          </div>

          {/* Product Information */}
          <div className="bg-gray-50 rounded-lg p-3">
            <h3 className="text-base font-semibold text-gray-900 mb-3">Product Information</h3>
            <div className="flex items-start gap-3">
              <div className="h-16 w-16 flex-shrink-0">
                {productInfo.image ? (
                  <img
                    className="h-16 w-16 rounded-lg object-cover"
                    src={productInfo.image}
                    alt={productInfo.name}
                    onError={handleImageError}
                  />
                ) : (
                  <div className="h-16 w-16 rounded-lg bg-gray-200 flex items-center justify-center">
                    <span className="text-gray-400 text-xs">No Image</span>
                  </div>
                )}
              </div>
              <div className="flex-1 min-w-0">
                <h4 className="text-sm font-medium text-gray-900 mb-1">{productInfo.name}</h4>
                <p className="text-xs text-gray-600">Product ID: {order.auction?.product?.productId || "N/A"}</p>
              </div>
            </div>
          </div>

          {/* Buyer and Seller Information */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Buyer Info */}
            <div className="bg-blue-50 rounded-lg p-3">
              <h3 className="text-base font-semibold text-gray-900 mb-3 flex items-center gap-2">
                <IoPerson size={16} />
                Buyer Information
              </h3>
              {order.user ? (
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Name:</span>
                    <span className="text-sm font-medium">{order.user.profile?.fullName || "N/A"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Email:</span>
                    <span className="text-sm font-medium truncate ml-2">{order.user.email}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Phone:</span>
                    <span className="text-sm font-medium">{order.user.profile?.phoneNumber || "N/A"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">User ID:</span>
                    <span className="text-xs font-medium">{order.user.userId}</span>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-gray-500">No buyer information available</p>
              )}
            </div>

            {/* Seller Info */}
            <div className="bg-green-50 rounded-lg p-3">
              <h3 className="text-base font-semibold text-gray-900 mb-3 flex items-center gap-2">
                <IoStorefront size={16} />
                Seller Information
              </h3>
              {order.auction?.seller ? (
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Name:</span>
                    <span className="text-sm font-medium">{order.auction.seller.profile?.fullName || "N/A"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Email:</span>
                    <span className="text-sm font-medium truncate ml-2">{order.auction.seller.email}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Phone:</span>
                    <span className="text-sm font-medium">{order.auction.seller.profile?.phoneNumber || "N/A"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">User ID:</span>
                    <span className="text-xs font-medium">{order.auction.seller.userId}</span>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-gray-500">No seller information available</p>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end p-4 border-t border-gray-200">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors duration-200 text-sm"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default OrderDetailsModal;
