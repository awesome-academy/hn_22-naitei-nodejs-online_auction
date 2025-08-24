import React, { useState } from "react";
import { IoClose, IoCheckmarkCircleOutline, IoSendOutline, IoWarning } from "react-icons/io5";
import { orderService } from "@/services/order.service";

const ConfirmShippedModal = ({ 
  isOpen, 
  onClose, 
  order, 
  onSuccess,
  formatCurrency 
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [trackingNumber, setTrackingNumber] = useState("");

  if (!isOpen || !order) return null;

  const handleConfirmShipped = async () => {
    try {
      setLoading(true);
      setError("");
      
      await orderService.confirmShipped(order.orderId, trackingNumber);
      
      // Call success callback to update the order status in parent component
      onSuccess(order.orderId, "SHIPPING");
      
      onClose();
      setTrackingNumber(""); // Reset form
    } catch (err) {
      console.error("Error confirming shipment:", err);
      setError(err.message || "Failed to confirm shipment");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-full">
              <IoSendOutline className="text-blue-600" size={20} />
            </div>
            <h2 className="text-lg font-semibold text-gray-900">
              Confirm Shipment
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
            disabled={loading}
          >
            <IoClose size={24} />
          </button>
        </div>

        {/* Content */}
        <div className="p-6">
          {/* Warning Message */}
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
            <div className="flex items-start gap-3">
              <IoWarning className="text-yellow-600 flex-shrink-0 mt-0.5" size={20} />
              <div>
                <p className="text-sm font-medium text-yellow-800">
                  Please confirm that you have shipped this order
                </p>
                <p className="text-sm text-yellow-700 mt-1">
                  This action cannot be undone. The order status will be updated to "SHIPPING".
                </p>
              </div>
            </div>
          </div>

          {/* Order Details */}
          <div className="space-y-3">
            <div>
              <p className="text-sm font-medium text-gray-700">Order ID</p>
              <p className="text-sm text-gray-900">#{order.orderId.slice(-8)}</p>
            </div>
            
            <div>
              <p className="text-sm font-medium text-gray-700">Auction</p>
              <p className="text-sm text-gray-900">{order.auction?.title || "N/A"}</p>
            </div>
            
            <div>
              <p className="text-sm font-medium text-gray-700">Buyer</p>
              <p className="text-sm text-gray-900">{order.user?.profile?.fullName || "N/A"}</p>
              <p className="text-xs text-gray-600">{order.user?.email || ""}</p>
            </div>
            
            <div>
              <p className="text-sm font-medium text-gray-700">Total Amount</p>
              <p className="text-lg font-bold text-gray-900">{formatCurrency(order.totalAmount)}</p>
            </div>
            
            <div>
              <p className="text-sm font-medium text-gray-700">Current Status</p>
              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                PAID
              </span>
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mt-4 bg-red-50 border border-red-200 rounded-lg p-3">
              <p className="text-sm text-red-800">{error}</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-3 p-6 border-t border-gray-200">
          <button
            onClick={onClose}
            className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
            disabled={loading}
          >
            Cancel
          </button>
          <button
            onClick={handleConfirmShipped}
            disabled={loading}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                Confirming...
              </>
            ) : (
              <>
                <IoCheckmarkCircleOutline size={16} />
                Confirm Shipped
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmShippedModal;
