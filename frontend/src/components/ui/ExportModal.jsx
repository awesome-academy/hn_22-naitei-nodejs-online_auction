import React, { useState } from 'react';
import { IoCloseOutline, IoDownloadOutline } from 'react-icons/io5';
import { PrimaryButton } from '@/components/ui/index.js';

const ExportModal = ({ isOpen, onClose, onExport, isLoading = false }) => {
    const [exportOptions, setExportOptions] = useState({
        status: '', // empty means all
    });

    const handleExport = () => {
        const params = {};
        if (exportOptions.status) {
            params.status = exportOptions.status;
        }
        onExport(params);
    };

    const handleClose = () => {
        setExportOptions({ status: '' });
        onClose();
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b border-gray-200">
                    <h3 className="text-lg font-semibold text-gray-900">
                        Export Products to Excel
                    </h3>
                    <button
                        onClick={handleClose}
                        className="text-gray-400 hover:text-gray-600 transition-colors"
                        disabled={isLoading}
                    >
                        <IoCloseOutline size={24} />
                    </button>
                </div>

                {/* Content */}
                <div className="p-6">
                    <div className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">
                                Filter by Status
                            </label>
                            <select
                                value={exportOptions.status}
                                onChange={(e) => setExportOptions({ ...exportOptions, status: e.target.value })}
                                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                disabled={isLoading}
                            >
                                <option value="">All Products</option>
                                <option value="ACTIVE">Active Products Only</option>
                                <option value="INACTIVE">Inactive Products Only</option>
                            </select>
                        </div>

                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                            <div className="flex">
                                <div className="ml-3">
                                    <h4 className="text-sm font-medium text-blue-900">
                                        Export Information
                                    </h4>
                                    <div className="mt-2 text-sm text-blue-700">
                                        <ul className="list-disc list-inside space-y-1">
                                            <li>Product details (ID, name, description, stock)</li>
                                            <li>Status and seller information</li>
                                            <li>Categories and primary image URL</li>
                                            <li>Creation and update dates</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Footer */}
                <div className="flex items-center justify-end gap-3 p-6 border-t border-gray-200">
                    <button
                        onClick={handleClose}
                        disabled={isLoading}
                        className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        Cancel
                    </button>
                    <PrimaryButton
                        onClick={handleExport}
                        disabled={isLoading}
                        className="bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white px-6 py-2 rounded-lg flex items-center gap-2 transition-colors duration-200"
                    >
                        {isLoading ? (
                            <>
                                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                                Exporting...
                            </>
                        ) : (
                            <>
                                <IoDownloadOutline size={16} />
                                Export Excel
                            </>
                        )}
                    </PrimaryButton>
                </div>
            </div>
        </div>
    );
};

export default ExportModal;
