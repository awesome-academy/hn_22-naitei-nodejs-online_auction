import React, { useState } from 'react';
import { IoCloseOutline, IoWarningOutline } from 'react-icons/io5';
import { PrimaryButton, SecondaryButton } from './index.js';

const CancelAuctionModal = ({
    isOpen,
    onClose,
    onConfirm,
    auction,
    loading = false
}) => {
    const [reason, setReason] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        if (reason.trim()) {
            onConfirm(auction.auctionId, reason.trim());
        }
    };

    const handleClose = () => {
        setReason('');
        onClose();
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
            <div className="bg-white rounded-lg max-w-md w-full mx-auto">
                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b border-gray-200">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
                            <IoWarningOutline className="text-red-600" size={20} />
                        </div>
                        <h3 className="text-lg font-semibold text-gray-900">
                            Cancel Auction
                        </h3>
                    </div>
                    <button
                        onClick={handleClose}
                        className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                    >
                        <IoCloseOutline size={20} className="text-gray-500" />
                    </button>
                </div>

                {/* Content */}
                <form onSubmit={handleSubmit} className="p-6">
                    <div className="mb-4">
                        <p className="text-gray-700 mb-2">
                            You are about to cancel the auction:
                            <span className="font-semibold"> "{auction?.title}"</span>
                        </p>
                        <p className="text-sm text-gray-500">
                            This action cannot be undone. Please provide a reason for cancellation.
                        </p>
                    </div>

                    <div className="mb-6">
                        <label htmlFor="cancel-reason" className="block text-sm font-medium text-gray-700 mb-2">
                            Reason for cancellation <span className="text-red-500">*</span>
                        </label>
                        <textarea
                            id="cancel-reason"
                            value={reason}
                            onChange={(e) => setReason(e.target.value)}
                            placeholder="Please provide a reason for cancelling this auction..."
                            rows={4}
                            required
                            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 resize-none"
                            disabled={loading}
                        />
                        <p className="text-xs text-gray-500 mt-1">
                            Minimum 10 characters required
                        </p>
                    </div>

                    {/* Actions */}
                    <div className="flex gap-3 justify-end">
                        <SecondaryButton
                            type="button"
                            onClick={handleClose}
                            disabled={loading}
                            className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
                        >
                            Keep Auction
                        </SecondaryButton>
                        <PrimaryButton
                            type="submit"
                            disabled={loading || reason.trim().length < 10}
                            className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
                        >
                            {loading ? 'Cancelling...' : 'Cancel Auction'}
                        </PrimaryButton>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default CancelAuctionModal;
