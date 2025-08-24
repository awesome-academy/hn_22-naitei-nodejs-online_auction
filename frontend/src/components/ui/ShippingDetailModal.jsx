import React from "react";
import { SHIPPING_STATUS_LABELS, SHIPPING_STATUS_COLORS } from "@/constants/shippingStatus.js";
import { formatVND, formatDate } from "@/utils/format.js";
import { 
  IoCloseOutline,
  IoBusinessOutline,
  IoPersonOutline,
  IoCallOutline,
  IoMailOutline,
  IoCarOutline,
  IoTimeOutline,
  IoCalendarOutline,
  IoLocationOutline,
  IoCodeWorkingOutline,
  IoCheckmarkCircleOutline,
  IoImageOutline,
  IoReceiptOutline,
  IoCardOutline,
  IoSpeedometerOutline,
  IoShieldCheckmarkOutline
} from "react-icons/io5";

const ShippingDetailModal = ({ shipping, isOpen, onClose, onConfirmDelivery }) => {
  const handleConfirmDelivery = () => {
    if (onConfirmDelivery) {
      onConfirmDelivery(shipping);
    }
  };

  if (!isOpen || !shipping) return null;

  const colors = SHIPPING_STATUS_COLORS[shipping.shippingStatus];
  
  const getStatusIcon = (status) => {
    switch (status) {
      case 'PENDING':
        return IoTimeOutline;
      case 'SHIPPED':
        return IoShieldCheckmarkOutline;
      case 'IN_TRANSIT':
        return IoSpeedometerOutline;
      case 'DELIVERED':
        return IoCheckmarkCircleOutline;
      default:
        return IoCarOutline;
    }
  };

  const StatusIcon = getStatusIcon(shipping.shippingStatus);

  const shippingTimeline = [
    {
      status: 'PENDING',
      label: 'Order Confirmed',
      date: shipping.createdAt,
      completed: true
    },
    {
      status: 'SHIPPED',
      label: 'Package Shipped',
      date: shipping.shippedAt,
      completed: shipping.shippedAt !== null
    },
    {
      status: 'IN_TRANSIT',
      label: 'In Transit',
      date: shipping.shippingStatus === 'IN_TRANSIT' ? shipping.updatedAt : null,
      completed: ['IN_TRANSIT', 'DELIVERED'].includes(shipping.shippingStatus)
    },
    {
      status: 'DELIVERED',
      label: 'Delivered',
      date: shipping.actualDelivery,
      completed: shipping.shippingStatus === 'DELIVERED'
    }
  ];

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <IoCarOutline className="w-6 h-6 text-green" />
            <h2 className="text-xl font-bold text-gray-900">Shipping Details</h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <IoCloseOutline className="w-6 h-6 text-gray-500" />
          </button>
        </div>

        <div className="p-6">
          {/* Current Status */}
          <div className="mb-8">
            <div className={`${colors.bg} ${colors.border} border rounded-lg p-6`}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <StatusIcon className={`w-8 h-8 ${colors.icon}`} />
                  <div>
                    <h3 className={`text-lg font-semibold ${colors.text}`}>
                      {SHIPPING_STATUS_LABELS[shipping.shippingStatus]}
                    </h3>
                    <p className="text-sm text-gray-600">
                      Last updated: {formatDate(shipping.updatedAt)}
                    </p>
                  </div>
                </div>
                {shipping.trackingNumber && (
                  <div className="text-right">
                    <p className="text-sm text-gray-600">Tracking Number</p>
                    <p className="font-mono font-semibold text-gray-900">{shipping.trackingNumber}</p>
                  </div>
                )}
              </div>

              {/* Timeline */}
              <div className="mt-6">
                <h4 className="font-medium text-gray-900 mb-4">Shipping Timeline</h4>
                <div className="space-y-3">
                  {shippingTimeline.map((step) => (
                    <div key={step.status} className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full ${step.completed ? 'bg-green' : 'bg-gray-300'}`} />
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <span className={`font-medium ${step.completed ? 'text-gray-900' : 'text-gray-500'}`}>
                            {step.label}
                          </span>
                          {step.date && (
                            <span className="text-sm text-gray-600">
                              {formatDate(step.date)}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Auction Information */}
            <div className="space-y-6">
              <div className="bg-gray-50 rounded-lg p-6">
                <h3 className="font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  <IoReceiptOutline className="w-5 h-5 text-gray-600" />
                  Auction Information
                </h3>
                
                <div className="space-y-4">
                  {/* Product */}
                  {shipping.auction?.product && (
                    <div className="flex gap-4">
                      {shipping.auction.product.images?.[0] ? (
                        <img
                          src={shipping.auction.product.images[0]}
                          alt={shipping.auction.product.name}
                          className="w-16 h-16 object-cover rounded-lg border border-gray-200"
                        />
                      ) : (
                        <div className="w-16 h-16 bg-gray-100 rounded-lg border border-gray-200 flex items-center justify-center">
                          <IoImageOutline className="w-6 h-6 text-gray-400" />
                        </div>
                      )}
                      <div className="flex-1">
                        <h4 className="font-medium text-gray-900">{shipping.auction.product.name}</h4>
                        <p className="text-sm text-gray-600">{shipping.auction.title}</p>
                      </div>
                    </div>
                  )}

                  {/* Auction Details */}
                  <div className="grid grid-cols-1 gap-3 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-600">Starting Price:</span>
                      <span className="font-medium">{formatVND(shipping.auction?.startingPrice)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Winning Bid:</span>
                      <span className="font-semibold text-green">{formatVND(shipping.auction?.winningBid)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Auction End:</span>
                      <span className="font-medium">{formatDate(shipping.auction?.endDate)}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Seller Information */}
              <div className="bg-gray-50 rounded-lg p-6">
                <h3 className="font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  <IoBusinessOutline className="w-5 h-5 text-gray-600" />
                  Seller Information
                </h3>
                
                <div className="space-y-3 text-sm">
                  <div className="flex items-center gap-3">
                    <IoPersonOutline className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-600">Name:</span>
                    <span className="font-medium">
                      {shipping.seller?.profile?.fullName || 'Not provided'}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <IoMailOutline className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-600">Email:</span>
                    <span className="font-medium">{shipping.seller?.email}</span>
                  </div>
                  {shipping.seller?.profile?.phoneNumber && (
                    <div className="flex items-center gap-3">
                      <IoCallOutline className="w-4 h-4 text-gray-400" />
                      <span className="text-gray-600">Phone:</span>
                      <span className="font-medium">{shipping.seller.profile.phoneNumber}</span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Shipping Information */}
            <div className="space-y-6">
              <div className="bg-gray-50 rounded-lg p-6">
                <h3 className="font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  <IoCarOutline className="w-5 h-5 text-gray-600" />
                  Shipping Information
                </h3>
                
                <div className="space-y-3 text-sm">
                  {shipping.price && (
                    <div className="flex justify-between">
                      <span className="text-gray-600">Shipping Cost:</span>
                      <span className="font-semibold text-green">{formatVND(shipping.price)}</span>
                    </div>
                  )}
                  
                  {shipping.trackingNumber && (
                    <div className="flex items-center gap-3">
                      <IoCodeWorkingOutline className="w-4 h-4 text-gray-400" />
                      <span className="text-gray-600">Tracking Number:</span>
                      <span className="font-mono font-medium">{shipping.trackingNumber}</span>
                    </div>
                  )}

                  {shipping.shippedAt && (
                    <div className="flex items-center gap-3">
                      <IoCalendarOutline className="w-4 h-4 text-gray-400" />
                      <span className="text-gray-600">Shipped Date:</span>
                      <span className="font-medium">{formatDate(shipping.shippedAt)}</span>
                    </div>
                  )}

                  {shipping.estimatedDelivery && (
                    <div className="flex items-center gap-3">
                      <IoTimeOutline className="w-4 h-4 text-gray-400" />
                      <span className="text-gray-600">Estimated Delivery:</span>
                      <span className="font-medium">{formatDate(shipping.estimatedDelivery)}</span>
                    </div>
                  )}

                  {shipping.actualDelivery && (
                    <div className="flex items-center gap-3">
                      <IoCheckmarkCircleOutline className="w-4 h-4 text-gray-400" />
                      <span className="text-gray-600">Actual Delivery:</span>
                      <span className="font-medium">{formatDate(shipping.actualDelivery)}</span>
                    </div>
                  )}

                  <div className="flex items-center gap-3">
                    <IoCalendarOutline className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-600">Order Created:</span>
                    <span className="font-medium">{formatDate(shipping.createdAt)}</span>
                  </div>
                </div>
              </div>

              {/* Buyer Information */}
              <div className="bg-gray-50 rounded-lg p-6">
                <h3 className="font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  <IoPersonOutline className="w-5 h-5 text-gray-600" />
                  Buyer Information (You)
                </h3>
                
                <div className="space-y-3 text-sm">
                  <div className="flex items-center gap-3">
                    <IoPersonOutline className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-600">Name:</span>
                    <span className="font-medium">
                      {shipping.buyer?.profile?.fullName || 'Not provided'}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <IoMailOutline className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-600">Email:</span>
                    <span className="font-medium">{shipping.buyer?.email}</span>
                  </div>
                  {shipping.buyer?.profile?.phoneNumber && (
                    <div className="flex items-center gap-3">
                      <IoCallOutline className="w-4 h-4 text-gray-400" />
                      <span className="text-gray-600">Phone:</span>
                      <span className="font-medium">{shipping.buyer.profile.phoneNumber}</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="mt-8 flex justify-end gap-3">
            <button
              onClick={onClose}
              className="px-6 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
            >
              Close
            </button>
            {shipping.shippingStatus === 'IN_TRANSIT' && (
              <button
                onClick={handleConfirmDelivery}
                className="px-6 py-2 bg-green text-white rounded-lg hover:bg-green-600 transition-colors flex items-center gap-2"
              >
                <IoCheckmarkCircleOutline className="w-4 h-4" />
                Confirm Delivery
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ShippingDetailModal;
