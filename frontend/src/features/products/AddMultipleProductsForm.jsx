import {
    Caption,
    Container,
    PrimaryButton,
    Title,
    commonClassNameOfInput,
} from "@/components/ui/index.js";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useNotification } from "@/contexts/NotificationContext.jsx";
import { useUser } from "@/contexts/UserContext.jsx";
import { useAddMultipleProducts } from "@/hooks/useAddMultipleProducts.js";
import { ExcelImport } from "@/components/ExcelImport/index.jsx";
import { IoCloudUploadOutline, IoImageOutline, IoTrashOutline, IoAddOutline, IoCloseOutline, IoGrid } from "react-icons/io5";

export const AddMultipleProductsForm = () => {
    const { user, loading } = useUser();
    const { showToastNotification } = useNotification();
    const navigate = useNavigate();
    const fileInputRefs = useRef([]);
    const [showExcelImport, setShowExcelImport] = useState(false);

    const {
        products,
        addProduct,
        importProductsFromExcel,
        clearAllProducts,
        removeProduct,
        updateProduct,
        handleImageUpload,
        removeImage,
        handleSubmit,
        error,
        loading: submitting,
        uploading,
    } = useAddMultipleProducts();

    useEffect(() => {
        if (!loading && (!user?.id || user?.role !== "SELLER")) {
            showToastNotification("You must be logged in as a seller to access this page", "error");
            navigate("/auth/login");
        }
    }, [loading, navigate, showToastNotification, user]);

    const handleFileSelect = (e, productIndex) => {
        const file = e.target.files[0];
        if (file) {
            handleImageUpload(file, productIndex);
        }
    };

    const triggerFileInput = (productIndex) => {
        fileInputRefs.current[productIndex]?.click();
    };

    const handleExcelImport = (importedProducts) => {
        importProductsFromExcel(importedProducts);
        setShowExcelImport(false);
    };

    const toggleExcelImport = () => {
        setShowExcelImport(!showExcelImport);
    };

    if (loading) {
        return <div>Loading...</div>;
    }

    return (
        <section className="add-multiple-products pt-16 relative">
            <div className="bg-green w-96 h-96 rounded-full opacity-20 blur-3xl absolute top-2/3"></div>

            <div className="bg-[#241C37] pt-8 h-[40vh] relative content">
                <Container>
                    <div>
                        <Title level={3} className="text-white">
                            Create multiple products
                        </Title>
                        <div className="flex items-center gap-3">
                            <Title level={5} className="text-green font-normal text-xl">Seller Hub</Title>
                            <Title level={5} className="text-white font-normal text-xl">/</Title>
                            <Title level={5} className="text-white font-normal text-xl">Add Multiple Products</Title>
                        </div>
                    </div>
                </Container>
            </div>

            <div className="transition-all duration-500 ease-in-out transform translate-x-0">
                <div className="bg-white shadow-s3 w-4/5 max-w-7xl m-auto my-16 p-8 rounded-xl">
                    <form onSubmit={handleSubmit}>
                        <div className="text-center mb-8">
                            <Title level={5}>Create multiple products at once</Title>
                            <Caption className="text-gray-600 mt-2">
                                Add multiple products to your inventory. All products will be created with ACTIVE status.
                            </Caption>
                        </div>

                        {error && (
                            <div className="text-center mb-6">
                                <div className="text-red-500 bg-red-50 p-3 rounded-md">{error}</div>
                            </div>
                        )}

                        {/* Excel Import Section */}
                        <div className="mb-8">
                            <div className="text-center mb-4">
                                <button
                                    type="button"
                                    onClick={toggleExcelImport}
                                    className="inline-flex items-center gap-2 px-6 py-3 bg-blue-500 text-white rounded-lg font-medium hover:bg-blue-600 transition-colors"
                                >
                                    <IoGrid size={20} />
                                    {showExcelImport ? 'Hide Excel Import' : 'Import from Excel'}
                                </button>
                            </div>

                            {showExcelImport && (
                                <div className="max-w-4xl mx-auto">
                                    <ExcelImport onImport={handleExcelImport} />
                                </div>
                            )}
                        </div>

                        {/* Control Buttons */}
                        <div className="mb-6 text-center space-x-4">
                            <button
                                type="button"
                                onClick={addProduct}
                                className="inline-flex items-center gap-2 px-6 py-3 bg-green text-white rounded-lg font-medium hover:bg-green-600 transition-colors"
                            >
                                <IoAddOutline size={20} />
                                Add Product
                            </button>

                            {products.length > 1 && (
                                <button
                                    type="button"
                                    onClick={clearAllProducts}
                                    className="inline-flex items-center gap-2 px-6 py-3 bg-red-500 text-white rounded-lg font-medium hover:bg-red-600 transition-colors"
                                >
                                    <IoTrashOutline size={20} />
                                    Clear All
                                </button>
                            )}

                            <div className="mt-2">
                                <Caption className="text-gray-600">
                                    Currently have {products.length} products (maximum 100)
                                </Caption>
                            </div>
                        </div>

                        {/* Products List */}
                        <div className="space-y-8">
                            {products.map((product, productIndex) => (
                                <div key={productIndex} className="border border-gray-200 rounded-lg p-6 relative">
                                    {/* Remove Product Button */}
                                    {products.length > 1 && (
                                        <button
                                            type="button"
                                            onClick={() => removeProduct(productIndex)}
                                            className="absolute top-4 right-4 text-red-500 hover:text-red-700 p-2"
                                        >
                                            <IoCloseOutline size={24} />
                                        </button>
                                    )}

                                    <div className="mb-4">
                                        <Title level={6} className="text-gray-800 font-semibold">
                                            Product {productIndex + 1}
                                        </Title>
                                    </div>

                                    {/* Photo Upload Section */}
                                    <div className="mb-6">
                                        <div className="flex items-center justify-between mb-4">
                                            <div>
                                                <Title level={6} className="text-gray-800 font-semibold">PHOTOS & VIDEOS</Title>
                                                <Caption className="text-gray-500">Add up to 10 photos</Caption>
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                                            {/* Add Photos Section */}
                                            <div
                                                onClick={() => triggerFileInput(productIndex)}
                                                className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center cursor-pointer hover:border-green hover:bg-green-50 transition-colors"
                                            >
                                                <IoImageOutline size={48} className="mx-auto mb-4 text-gray-400" />
                                                <p className="text-gray-600 font-medium">Add photo</p>
                                                <Caption className="text-gray-500">or drag and drop here</Caption>
                                                {uploading === productIndex && (
                                                    <div className="mt-2">
                                                        <Caption className="text-blue-500">Uploading...</Caption>
                                                    </div>
                                                )}
                                            </div>

                                            {/* Add Video Section - Placeholder */}
                                            <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center cursor-not-allowed opacity-50">
                                                <IoCloudUploadOutline size={48} className="mx-auto mb-4 text-gray-400" />
                                                <p className="text-gray-600 font-medium">Add video</p>
                                                <Caption className="text-gray-500">or drag and drop here</Caption>
                                            </div>
                                        </div>

                                        {/* Uploaded Images Display */}
                                        {product.uploadedImages.length > 0 && (
                                            <div className="mb-6">
                                                <Caption className="mb-3 text-gray-700">Uploaded photos ({product.uploadedImages.length})</Caption>
                                                <div className="grid grid-cols-4 gap-3">
                                                    {product.uploadedImages.map((imageUrl, index) => (
                                                        <div key={index} className="relative group">
                                                            <img
                                                                src={imageUrl}
                                                                alt={`Product ${productIndex + 1} - ${index + 1}`}
                                                                className="w-full h-24 object-cover rounded-lg border border-gray-200"
                                                            />
                                                            <button
                                                                type="button"
                                                                onClick={() => removeImage(productIndex, index)}
                                                                className="absolute top-1 right-1 bg-red-500 text-white p-1 rounded-full opacity-0 group-hover:opacity-100 transition-opacity"
                                                            >
                                                                <IoTrashOutline size={12} />
                                                            </button>
                                                            {index === 0 && (
                                                                <div className="absolute bottom-1 left-1 bg-blue-500 text-white text-xs px-1 rounded">
                                                                    Main
                                                                </div>
                                                            )}
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        <input
                                            ref={el => fileInputRefs.current[productIndex] = el}
                                            type="file"
                                            accept="image/*"
                                            onChange={(e) => handleFileSelect(e, productIndex)}
                                            className="hidden"
                                        />
                                    </div>

                                    {/* Product Info */}
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        {/* Product Name */}
                                        <div>
                                            <Caption className="mb-2 text-gray-700">Product Name *</Caption>
                                            <input
                                                type="text"
                                                value={product.productName}
                                                onChange={(e) => updateProduct(productIndex, 'productName', e.target.value)}
                                                className={`${commonClassNameOfInput} w-full`}
                                                placeholder="Enter product name"
                                                required
                                            />
                                        </div>

                                        {/* Stock Quantity */}
                                        <div>
                                            <Caption className="mb-2 text-gray-700">Stock Quantity *</Caption>
                                            <input
                                                type="number"
                                                value={product.stockQuantity}
                                                onChange={(e) => updateProduct(productIndex, 'stockQuantity', e.target.value)}
                                                className={`${commonClassNameOfInput} w-full`}
                                                placeholder="Enter quantity"
                                                min="0"
                                                required
                                            />
                                        </div>
                                    </div>

                                    {/* Description */}
                                    <div className="mt-6">
                                        <Caption className="mb-2 text-gray-700">Product Description</Caption>
                                        <textarea
                                            value={product.description}
                                            onChange={(e) => updateProduct(productIndex, 'description', e.target.value)}
                                            className={`${commonClassNameOfInput} w-full min-h-[120px] resize-vertical`}
                                            placeholder="Detailed product description..."
                                            rows={4}
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Create for free section */}
                        <div className="mb-8 p-6 bg-gray-50 rounded-lg text-center mt-8">
                            <Title level={6} className="text-gray-800 mb-2">Create multiple products for free.</Title>
                            <Caption className="text-gray-600">
                                Connect with millions of buyers and grow your business faster
                            </Caption>
                        </div>

                        {/* Action Buttons */}
                        <div className="flex gap-4 justify-center">
                            <PrimaryButton
                                type="submit"
                                className="px-8 py-3 bg-green text-white rounded-lg font-medium hover:bg-green-600 transition-colors disabled:opacity-50"
                                disabled={submitting || uploading !== null}
                            >
                                {submitting ? `Creating ${products.length} Products...` : `Create ${products.length} Product${products.length > 1 ? 's' : ''}`}
                            </PrimaryButton>

                            <button
                                type="button"
                                onClick={() => navigate("/seller-hub/listings/product")}
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
