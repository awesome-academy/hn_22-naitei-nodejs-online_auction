import { useState, useRef } from 'react';
import { readExcelFile, downloadSampleExcel } from '@/utils/excelUtils.js';
import { Caption } from '@/components/ui/index.js';
import { IoCloudUploadOutline, IoDocumentTextOutline, IoDownloadOutline, IoCheckmarkCircleOutline, IoCloseCircleOutline } from 'react-icons/io5';

export const ExcelImport = ({ onImport, className = '' }) => {
    const [isProcessing, setIsProcessing] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [isDragOver, setIsDragOver] = useState(false);
    const fileInputRef = useRef(null);

    const handleFileSelect = async (file) => {
        if (!file) return;

        // Validate file type
        const validTypes = [
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // .xlsx
            'application/vnd.ms-excel', // .xls
        ];

        if (!validTypes.includes(file.type)) {
            setError('Please select an Excel file (.xlsx or .xls)');
            setSuccess('');
            return;
        }

        // Validate file size (max 10MB)
        const maxSize = 10 * 1024 * 1024;
        if (file.size > maxSize) {
            setError('File size cannot exceed 10MB');
            setSuccess('');
            return;
        }

        setIsProcessing(true);
        setError('');
        setSuccess('');

        try {
            const products = await readExcelFile(file);

            if (products.length > 100) {
                setError('Cannot import more than 100 products at once');
                setIsProcessing(false);
                return;
            }

            onImport(products);
            setSuccess(`Successfully imported ${products.length} products from Excel`);

            // Reset file input
            if (fileInputRef.current) {
                fileInputRef.current.value = '';
            }
        } catch (err) {
            console.error('Excel import error:', err);
            setError(err.message || 'An error occurred while reading the Excel file');
        } finally {
            setIsProcessing(false);
        }
    };

    const handleFileInputChange = async (e) => {
        const file = e.target.files[0];
        await handleFileSelect(file);
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragOver(true);
    };

    const handleDragLeave = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragOver(false);
    };

    const handleDrop = async (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragOver(false);

        const files = Array.from(e.dataTransfer.files);
        if (files.length > 0) {
            await handleFileSelect(files[0]);
        }
    };

    const triggerFileInput = () => {
        fileInputRef.current?.click();
    };

    const handleDownloadSample = () => {
        try {
            downloadSampleExcel();
            setError('');
        } catch (err) {
            console.error('Download sample error:', err);
            setError('An error occurred while downloading the sample file');
        }
    };

    return (
        <div className={`excel-import ${className}`}>
            {/* Import Section */}
            <div
                className={`border-2 border-dashed rounded-lg p-6 text-center transition-colors cursor-pointer ${isDragOver
                        ? 'border-green-500 bg-green-100'
                        : 'border-gray-300 hover:border-green hover:bg-green-50'
                    }`}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={triggerFileInput}
            >
                <div className="mb-4">
                    <IoCloudUploadOutline
                        size={48}
                        className={`mx-auto transition-colors ${isDragOver ? 'text-green-500' : 'text-gray-400'
                            }`}
                    />
                </div>

                <div className="mb-4">
                    <h3 className="text-lg font-semibold text-gray-800 mb-2">
                        {isDragOver ? 'Drop file here' : 'Import from Excel'}
                    </h3>
                    <Caption className="text-gray-600">
                        {isDragOver
                            ? 'Release to upload Excel file'
                            : 'Click to select or drag & drop Excel file here'
                        }
                    </Caption>
                </div>

                {/* Buttons */}
                <div className="flex flex-col sm:flex-row gap-3 justify-center items-center mb-4" onClick={(e) => e.stopPropagation()}>
                    <button
                        type="button"
                        onClick={triggerFileInput}
                        disabled={isProcessing}
                        className="inline-flex items-center gap-2 px-6 py-3 bg-green text-white rounded-lg font-medium hover:bg-green-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        <IoDocumentTextOutline size={20} />
                        {isProcessing ? 'Processing...' : 'Select Excel file'}
                    </button>

                    <button
                        type="button"
                        onClick={handleDownloadSample}
                        className="inline-flex items-center gap-2 px-6 py-3 bg-white border border-gray-300 text-gray-700 rounded-lg font-medium hover:bg-gray-50 transition-colors"
                    >
                        <IoDownloadOutline size={20} />
                        Download sample file
                    </button>
                </div>

                {/* File format info */}
                <div className="text-sm text-gray-500">
                    <p>Supported: .xlsx, .xls (max 10MB, 100 products)</p>
                </div>

                {/* Hidden file input */}
                <input
                    ref={fileInputRef}
                    type="file"
                    accept=".xlsx,.xls,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-excel"
                    onChange={handleFileInputChange}
                    className="hidden"
                />
            </div>

            {/* Status Messages */}
            {error && (
                <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
                    <div className="flex items-center gap-2 text-red-700">
                        <IoCloseCircleOutline size={20} />
                        <span className="font-medium">Error:</span>
                    </div>
                    <p className="text-red-600 mt-1">{error}</p>
                </div>
            )}

            {success && (
                <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-lg">
                    <div className="flex items-center gap-2 text-green-700">
                        <IoCheckmarkCircleOutline size={20} />
                        <span className="font-medium">Success:</span>
                    </div>
                    <p className="text-green-600 mt-1">{success}</p>
                </div>
            )}

            {/* Instructions */}
            <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <h4 className="font-semibold text-blue-800 mb-2">Usage Instructions:</h4>
                <ul className="text-blue-700 text-sm space-y-1">
                    <li>1. Download the sample Excel file to see the required format</li>
                    <li>2. Fill in product information in the Excel file</li>
                    <li>3. Required columns: Product Name, Stock Quantity</li>
                    <li>4. Optional column: Description</li>
                    <li>5. Click to select file or drag & drop Excel file to import data</li>
                </ul>
            </div>
        </div>
    );
};
