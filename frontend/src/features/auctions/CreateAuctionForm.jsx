import React, { useEffect, useState } from 'react';
import {
    Caption,
    Container,
    PrimaryButton,
    Title,
    commonClassNameOfInput,
} from "@/components/ui/index.js";
import { useNavigate } from "react-router-dom";
import { useNotification } from "@/contexts/NotificationContext.jsx";
import { useUser } from "@/contexts/UserContext.jsx";
import { useCreateAuction } from "@/hooks/useCreateAuction.js";
import { IoImageOutline, IoCloudUploadOutline, IoCloseOutline, IoCheckmarkOutline } from "react-icons/io5";

export const CreateAuctionForm = () => {
    const { user, loading } = useUser();
    const { showToastNotification } = useNotification();
    const navigate = useNavigate();
    const [showProductSelector, setShowProductSelector] = useState(false);

    const {
        title,
        setTitle,
        startTime,
        setStartTime,
        endTime,
        setEndTime,
        startingPrice,
        setStartingPrice,
        minimumBidIncrement,
        setMinimumBidIncrement,
        selectedProducts,
        availableProducts,
        loadingProducts,
        error,
        submitting,
        loadAvailableProducts,
        addProduct,
        removeProduct,
        updateProductQuantity,
        handleSubmit,
    } = useCreateAuction();

    useEffect(() => {
        if (!loading && (!user?.id || user?.role !== "SELLER")) {
            showToastNotification("You must be logged in as a seller to access this page", "error");
            navigate("/auth/login");
        }
    }, [loading, navigate, showToastNotification, user]);

    useEffect(() => {
        if (user?.id && user?.role === "SELLER") {
            loadAvailableProducts();
        }
    }, [user, loadAvailableProducts]);

    // Debug log to check if products are loaded
    useEffect(() => {
        console.log('Available products:', availableProducts);
        console.log('Loading products:', loadingProducts);
    }, [availableProducts, loadingProducts]); const formatDateTime = (dateTimeString) => {
        if (!dateTimeString) return '';
        const date = new Date(dateTimeString);
        return date.toLocaleString('en-US', {
            month: 'short',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        });
    };

    const getMinDateTime = () => {
        const now = new Date();
        now.setMinutes(now.getMinutes() + 30); // Minimum 30 minutes from now
        return now.toISOString().slice(0, 16);
    };

    const getMinEndDateTime = () => {
        if (!startTime) return getMinDateTime();
        const start = new Date(startTime);
        start.setHours(start.getHours() + 1); // Minimum 1 hour after start
        return start.toISOString().slice(0, 16);
    };

    if (loading) {
        return <div className="flex justify-center items-center h-64">Loading...</div>;
    }

    return (
        <section className="create-auction pt-16 relative">
            <div className="bg-green w-96 h-96 rounded-full opacity-20 blur-3xl absolute top-2/3"></div>

            <div className="bg-[#241C37] pt-8 h-[40vh] relative content">
                <Container>
                    <div>
                        <Title level={1} className="text-white text-4xl mb-4">
                            Create your auction
                        </Title>
                        <div className="flex items-center gap-3">
                            <Title level={5} className="text-green font-normal text-xl">Seller Hub</Title>
                            <Title level={5} className="text-white font-normal text-xl">/</Title>
                            <Title level={5} className="text-white font-normal text-xl">Create Auction</Title>
                        </div>
                    </div>
                </Container>
            </div>

            <div className="transition-all duration-500 ease-in-out transform translate-x-0">
                <div className="bg-white shadow-s3 w-4/5 max-w-6xl m-auto my-16 p-8 rounded-xl">
                    <form onSubmit={handleSubmit}>
                        {error && (
                            <div className="text-center mb-6">
                                <div className="text-red-500 bg-red-50 p-3 rounded-md">{error}</div>
                            </div>
                        )}

                        {/* Product Setting Section */}
                        <div className="mb-8">
                            <div className="flex items-center justify-between mb-4">
                                <div>
                                    <Title level={5} className="text-gray-800 font-semibold">Product Setting</Title>
                                    <Caption className="text-gray-500">PHOTO & VIDEO</Caption>
                                    <Caption className="text-gray-500">0 of 24 photos</Caption>
                                </div>
                                <button
                                    type="button"
                                    onClick={() => setShowProductSelector(!showProductSelector)}
                                    className="px-6 py-2 bg-green text-white rounded-full font-medium hover:bg-green-600 transition-colors"
                                >
                                    Select active products
                                </button>
                            </div>

                            <div className="grid grid-cols-2 gap-4 mb-6">
                                {/* Add Photos Section - Placeholder */}
                                <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center cursor-not-allowed opacity-50">
                                    <IoImageOutline size={48} className="mx-auto mb-4 text-gray-400" />
                                    <p className="text-gray-600 font-medium">Add photos</p>
                                    <Caption className="text-gray-500">or drag and drop</Caption>
                                </div>

                                {/* Add Video Section - Placeholder */}
                                <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center cursor-not-allowed opacity-50">
                                    <IoCloudUploadOutline size={48} className="mx-auto mb-4 text-gray-400" />
                                    <p className="text-gray-600 font-medium">Add video</p>
                                    <Caption className="text-gray-500">or drag and drop</Caption>
                                </div>
                            </div>
                        </div>

                        {/* Product Selector Modal */}
                        {showProductSelector && (
                            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                                <div className="bg-white rounded-lg max-w-4xl w-full max-h-[80vh] overflow-y-auto m-4">
                                    <div className="p-6 border-b border-gray-200">
                                        <div className="flex justify-between items-center">
                                            <div>
                                                <Title level={4}>Select Active Products for Auction</Title>
                                                <Caption className="text-gray-500 mt-1">Only products with ACTIVE status and available stock are shown</Caption>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <button
                                                    type="button"
                                                    onClick={loadAvailableProducts}
                                                    disabled={loadingProducts}
                                                    className="px-3 py-1 bg-blue-500 text-white rounded text-sm hover:bg-blue-600 disabled:opacity-50"
                                                >
                                                    {loadingProducts ? "Loading..." : "Refresh"}
                                                </button>
                                                <button
                                                    type="button"
                                                    onClick={() => setShowProductSelector(false)}
                                                    className="text-gray-400 hover:text-gray-600"
                                                >
                                                    <IoCloseOutline size={24} />
                                                </button>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="p-6">
                                        {loadingProducts ? (
                                            <div className="text-center py-8">Loading products...</div>
                                        ) : availableProducts.length === 0 ? (
                                            <div className="text-center py-8">
                                                <p className="text-gray-500">No active products available</p>
                                                <p className="text-sm text-gray-400 mt-2">Only products with ACTIVE status and stock are shown here</p>
                                                <p className="text-sm text-gray-400">Make sure your products are active and have stock before creating auctions</p>
                                            </div>
                                        ) : (
                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                {availableProducts.map((product) => {
                                                    const isSelected = selectedProducts.some(p => p.productId === product.productId);
                                                    const selectedProduct = selectedProducts.find(p => p.productId === product.productId);
                                                    const primaryImage = product.images?.find(img => img.isPrimary) || product.images?.[0];

                                                    return (
                                                        <div
                                                            key={product.productId}
                                                            className={`border rounded-lg p-4 ${isSelected ? 'border-green bg-green-50' : 'border-gray-200'}`}
                                                        >
                                                            <div className="flex items-start gap-3">
                                                                {primaryImage && (
                                                                    <img
                                                                        src={primaryImage.imageUrl}
                                                                        alt={product.name}
                                                                        className="w-16 h-16 object-cover rounded-lg flex-shrink-0"
                                                                    />
                                                                )}
                                                                <div className="flex-1 min-w-0">
                                                                    <h3 className="font-medium text-gray-900 truncate">{product.name}</h3>
                                                                    <p className="text-sm text-gray-500 mt-1">Stock: {product.stockQuantity}</p>
                                                                </div>
                                                                <div className="flex-shrink-0">
                                                                    {isSelected ? (
                                                                        <div className="flex items-center gap-2">
                                                                            <IoCheckmarkOutline size={20} className="text-green" />
                                                                            <button
                                                                                type="button"
                                                                                onClick={() => removeProduct(product.productId)}
                                                                                className="text-red-500 hover:text-red-700"
                                                                            >
                                                                                <IoCloseOutline size={20} />
                                                                            </button>
                                                                        </div>
                                                                    ) : (
                                                                        <button
                                                                            type="button"
                                                                            onClick={() => addProduct(product, 1)}
                                                                            className="px-3 py-1 bg-green text-white rounded text-sm hover:bg-green-600"
                                                                        >
                                                                            Add
                                                                        </button>
                                                                    )}
                                                                </div>
                                                            </div>

                                                            {isSelected && (
                                                                <div className="mt-3 flex items-center gap-2">
                                                                    <label className="text-sm text-gray-700">Quantity:</label>
                                                                    <input
                                                                        type="number"
                                                                        min="1"
                                                                        max={product.stockQuantity}
                                                                        value={selectedProduct?.quantity || 1}
                                                                        onChange={(e) => updateProductQuantity(product.productId, parseInt(e.target.value))}
                                                                        className="w-20 px-2 py-1 border border-gray-300 rounded text-sm"
                                                                    />
                                                                </div>
                                                            )}
                                                        </div>
                                                    );
                                                })}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Selected Products Display */}
                        {selectedProducts.length > 0 && (
                            <div className="mb-8">
                                <Title level={6} className="text-gray-800 font-semibold mb-4">Selected Products</Title>
                                <div className="space-y-3">
                                    {selectedProducts.map((selectedProduct) => (
                                        <div key={selectedProduct.productId} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                            <div>
                                                <h4 className="font-medium">{selectedProduct.product?.name || selectedProduct.productId}</h4>
                                                <p className="text-sm text-gray-500">Quantity: {selectedProduct.quantity}</p>
                                            </div>
                                            <button
                                                type="button"
                                                onClick={() => removeProduct(selectedProduct.productId)}
                                                className="text-red-500 hover:text-red-700"
                                            >
                                                <IoCloseOutline size={20} />
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Title Section */}
                        <div className="mb-8">
                            <div className="flex items-center justify-between mb-4">
                                <Title level={6} className="text-gray-800 font-semibold">TITLE</Title>
                                <Caption className="text-blue-500 cursor-pointer hover:underline">
                                    See photo options
                                </Caption>
                            </div>

                            <div className="mb-2">
                                <div className="flex items-start gap-2 p-3 bg-blue-50 rounded-md mb-4">
                                    <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0"></div>
                                    <Caption className="text-blue-700">
                                        Provide a title for your auction. Use words people would search for when looking for your auction.
                                    </Caption>
                                </div>
                            </div>

                            <div>
                                <Caption className="mb-2 text-gray-700">Auction title *</Caption>
                                <input
                                    type="text"
                                    name="title"
                                    value={title}
                                    onChange={(e) => setTitle(e.target.value)}
                                    className={`${commonClassNameOfInput} w-full`}
                                    placeholder="Enter auction title"
                                    required
                                />
                            </div>
                        </div>

                        {/* Auction Settings Section */}
                        <div className="mb-8">
                            <Title level={6} className="text-gray-800 font-semibold mb-4">Auction Settings</Title>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div>
                                    <Caption className="mb-2 text-gray-700">Start time *</Caption>
                                    <input
                                        type="datetime-local"
                                        name="startTime"
                                        value={startTime}
                                        onChange={(e) => setStartTime(e.target.value)}
                                        min={getMinDateTime()}
                                        className={`${commonClassNameOfInput} w-full`}
                                        required
                                    />
                                    {startTime && (
                                        <Caption className="text-gray-500 mt-1">
                                            Starts: {formatDateTime(startTime)}
                                        </Caption>
                                    )}
                                </div>

                                <div>
                                    <Caption className="mb-2 text-gray-700">End time *</Caption>
                                    <input
                                        type="datetime-local"
                                        name="endTime"
                                        value={endTime}
                                        onChange={(e) => setEndTime(e.target.value)}
                                        min={getMinEndDateTime()}
                                        className={`${commonClassNameOfInput} w-full`}
                                        required
                                    />
                                    {endTime && (
                                        <Caption className="text-gray-500 mt-1">
                                            Ends: {formatDateTime(endTime)}
                                        </Caption>
                                    )}
                                </div>

                                <div>
                                    <Caption className="mb-2 text-gray-700">Starting price (USD) *</Caption>
                                    <input
                                        type="number"
                                        name="startingPrice"
                                        value={startingPrice}
                                        onChange={(e) => setStartingPrice(e.target.value)}
                                        min="0.01"
                                        step="0.01"
                                        className={`${commonClassNameOfInput} w-full`}
                                        placeholder="99.99"
                                        required
                                    />
                                </div>

                                <div>
                                    <Caption className="mb-2 text-gray-700">Minimum bid increment (USD) *</Caption>
                                    <input
                                        type="number"
                                        name="minimumBidIncrement"
                                        value={minimumBidIncrement}
                                        onChange={(e) => setMinimumBidIncrement(e.target.value)}
                                        min="0.01"
                                        step="0.01"
                                        className={`${commonClassNameOfInput} w-full`}
                                        placeholder="5.00"
                                        required
                                    />
                                </div>
                            </div>
                        </div>

                        {/* Create for free section */}
                        <div className="mb-8 p-6 bg-gray-50 rounded-lg text-center">
                            <Title level={5} className="text-gray-800 mb-2">Create for free.</Title>
                            <Caption className="text-gray-600">
                                By clicking "Create auction", you agree to our Terms of Service and Privacy Policy.
                                You agree to be responsible for the accuracy of the auction information and to comply with all applicable laws.
                            </Caption>
                        </div>

                        {/* Action Buttons */}
                        <div className="flex gap-4 justify-center">
                            <PrimaryButton
                                type="submit"
                                className="px-8 py-3 bg-green text-white rounded-lg font-medium hover:bg-green-600 transition-colors disabled:opacity-50"
                                disabled={submitting || selectedProducts.length === 0}
                            >
                                {submitting ? "Creating auction..." : "Create auction"}
                            </PrimaryButton>

                            <button
                                type="button"
                                className="px-8 py-3 bg-white border border-gray-300 text-gray-700 rounded-lg font-medium hover:bg-gray-50 transition-colors"
                            >
                                Save for later
                            </button>

                            <button
                                type="button"
                                onClick={() => navigate("/seller-hub/listings/auction")}
                                className="px-8 py-3 bg-white border border-gray-300 text-gray-700 rounded-lg font-medium hover:bg-gray-50 transition-colors"
                            >
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </section>
    );
};
