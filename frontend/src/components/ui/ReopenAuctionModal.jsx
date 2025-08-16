import React, { useState } from 'react';
import { IoCloseOutline, IoRefreshOutline } from 'react-icons/io5';
import { PrimaryButton, SecondaryButton } from './index.js';

const ReopenAuctionModal = ({
    isOpen,
    onClose,
    onConfirm,
    auction,
    loading = false
}) => {
    const handleSubmit = (e) => {
        e.preventDefault();
        onConfirm(auction);
    };

    const handleClose = () => {
        onClose();
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
            <div className="bg-white rounded-lg max-w-md w-full mx-auto">
                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b border-gray-200">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center">
                            <IoRefreshOutline className="text-green-600" size={20} />
                        </div>
                        <h3 className="text-lg font-semibold text-gray-900">
                            Reopen Auction
                        </h3>
                    </div>
                    <button
                        onClick={handleClose}
                        className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                        disabled={loading}
                    >
                        <IoCloseOutline size={20} className="text-gray-500" />
                    </button>
                </div>

                {/* Content */}
                <form onSubmit={handleSubmit} className="p-6">
                    <div className="mb-6">
                        <p className="text-gray-700 mb-2">
                            You are about to reopen the auction:
                            <span className="font-semibold"> "{auction?.title}"</span>
                        </p>
                        <p className="text-sm text-gray-500">
                            Once reopened, the auction will be set to PENDING status and will need admin approval before it can go live again.
                        </p>
                    </div>

                    <div className="mb-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                        <div className="flex items-start gap-2">
                            <div className="w-1 h-1 bg-yellow-500 rounded-full mt-2 flex-shrink-0"></div>
                            <div>
                                <p className="text-sm text-yellow-800 font-medium mb-1">Important Note:</p>
                                <p className="text-sm text-yellow-700">
                                    The auction will require admin approval before it becomes active. 
                                    You may need to update auction details if required.
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Actions */}
                    <div className="flex gap-3 justify-end">
                        <SecondaryButton
                            type="button"
                            onClick={handleClose}
                            disabled={loading}
                            className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
                        >
                            Cancel
                        </SecondaryButton>
                        <PrimaryButton
                            type="submit"
                            disabled={loading}
                            className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
                        >
                            {loading ? 'Reopening...' : 'Reopen Auction'}
                        </PrimaryButton>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default ReopenAuctionModal;
