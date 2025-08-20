import React, { useEffect, useState } from 'react';
import { 
  IoCheckmarkCircleOutline, 
  IoCloseOutline, 
  IoWarningOutline 
} from 'react-icons/io5';

const ConfirmDeliveryModal = ({ 
  isOpen, 
  onClose, 
  onConfirm, 
  auctionTitle, 
  isLoading = false 
}) => {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setIsVisible(true);
    } else {
      const timer = setTimeout(() => setIsVisible(false), 300);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  if (!isVisible) return null;

  const handleBackdropClick = (e) => {
    if (e.target === e.currentTarget && !isLoading) {
      onClose();
    }
  };

  const handleConfirm = async () => {
    try {
      await onConfirm();
      // Modal will be closed automatically by the parent component after successful confirmation
    } catch (error) {
      // Error handling is done in the parent component
      console.error('Confirm delivery error:', error);
    }
  };

  return (
    <div 
      className={`fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4 transition-opacity duration-300 ${
        isOpen ? 'opacity-100' : 'opacity-0'
      }`}
      onClick={handleBackdropClick}
    >
      <div className={`bg-white rounded-xl shadow-2xl max-w-md w-full mx-4 overflow-hidden transform transition-all duration-300 ${
        isOpen ? 'scale-100 translate-y-0' : 'scale-95 -translate-y-4'
      }`}>
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-500 to-blue-600 p-6 text-white relative">
          <button
            onClick={onClose}
            disabled={isLoading}
            className="absolute top-4 right-4 text-white hover:bg-white hover:bg-opacity-20 rounded-full p-1 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <IoCloseOutline className="w-6 h-6" />
          </button>
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-white bg-opacity-20 rounded-full flex items-center justify-center">
              <IoCheckmarkCircleOutline className="w-7 h-7" />
            </div>
            <div>
              <h2 className="text-xl font-bold">Confirm Delivery</h2>
              <p className="text-blue-100 text-sm">Mark this shipment as delivered</p>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="p-6">
          <div className="flex items-start gap-3 mb-6">
            <div className="w-10 h-10 bg-yellow-100 rounded-full flex items-center justify-center flex-shrink-0 mt-1">
              <IoWarningOutline className="w-5 h-5 text-yellow-600" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 mb-2">Important Notice</h3>
              <p className="text-gray-600 text-sm leading-relaxed">
                By confirming delivery, you acknowledge that you have received the item for:
              </p>
            </div>
          </div>

          <div className="bg-gray-50 rounded-lg p-4 mb-6">
            <p className="text-sm text-gray-600 mb-1">Auction Title:</p>
            <p className="font-semibold text-gray-900">{auctionTitle}</p>
          </div>

          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <p className="text-blue-800 text-sm">
              <strong>Note:</strong> This action cannot be undone. Please only confirm if you have actually received the item in good condition.
            </p>
          </div>

          {/* Actions */}
          <div className="flex gap-3">
            <button
              onClick={onClose}
              disabled={isLoading}
              className="flex-1 px-4 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Cancel
            </button>
            <button
              onClick={handleConfirm}
              disabled={isLoading}
              className="flex-1 px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  Processing...
                </>
              ) : (
                <>
                  <IoCheckmarkCircleOutline className="w-4 h-4" />
                  Confirm Delivery
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ConfirmDeliveryModal;
