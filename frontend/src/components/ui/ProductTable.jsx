import React from "react";
import { IoCreateOutline, IoTrashOutline, IoToggleOutline, IoCheckmarkCircleOutline, IoCloseCircleOutline } from "react-icons/io5";
import { PRODUCT_STATUS, getProductStatusConfig } from "@/constants/productStatus.js";

export const ProductTable = ({ products, onEdit, onDelete, onToggleStatus, toggleLoading }) => {
  const getStatusBadge = (status) => {
    const config = getProductStatusConfig(status);
    const IconComponent = config.icon;

    return (
      <span
        className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium ${config.bg} ${config.text}`}
        title={config.tooltip}
      >
        <IconComponent size={14} className={config.animateIcon ? "animate-spin" : ""} />
        {config.label}
      </span>
    );
  };

  const getCategoryBadges = (categories) => {
    if (!categories || categories.length === 0) return null;

    return (
      <div className="flex flex-wrap gap-1">
        {categories.map((category, index) => (
          <span
            key={`${category}-${index}`}
            className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800"
          >
            {category}
          </span>
        ))}
      </div>
    );
  };

  if (!products || products.length === 0) {
    return (
      <div className="bg-white border border-gray-300 rounded-lg p-8 text-center">
        <p className="text-gray-500 text-lg">No products found</p>
        <p className="text-gray-400 text-sm mt-2">Create your first product to get started</p>
      </div>
    );
  }

  return (
    <div className="bg-white border border-gray-300 rounded-lg overflow-hidden">
      {/* Table Header */}
      <div className="bg-gray-50 px-6 py-3 border-b border-gray-200">
        <div className="grid grid-cols-12 gap-4 text-sm font-medium text-gray-700">
          <div className="col-span-4">Product</div>
          <div className="col-span-3">Categories</div>
          <div className="col-span-2">Stock</div>
          <div className="col-span-2">Status</div>
          <div className="col-span-1">Actions</div>
        </div>
      </div>

      {/* Table Body */}
      <div className="divide-y divide-gray-200">
        {products.map((product) => (
          <div key={product.productId} className="px-6 py-4 hover:bg-gray-50 transition-colors duration-200">
            <div className="grid grid-cols-12 gap-4 items-center">
              {/* Product Info */}
              <div className="col-span-4 flex items-center space-x-3">
                <div className="w-16 h-16 bg-gray-200 rounded-lg overflow-hidden flex-shrink-0">
                  {product.images && product.images.length > 0 ? (
                    <img
                      src={product.images[0].imageUrl}
                      alt={product.name}
                      className="w-full h-full object-cover"
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center text-gray-400">
                      <span className="text-xs">No Image</span>
                    </div>
                  )}
                </div>
                <div className="min-w-0 flex-1">
                  <h3 className="text-sm font-medium text-gray-900 truncate">
                    {product.name}
                  </h3>
                  <p className="text-sm text-gray-500 truncate mt-1">
                    {product.description}
                  </p>
                </div>
              </div>

              {/* Categories */}
              <div className="col-span-3">
                {getCategoryBadges(product.categories || ["General"])}
              </div>

              {/* Stock */}
              <div className="col-span-2">
                <span className="text-sm text-gray-900">
                  {product.stockQuantity || 0} units
                </span>
              </div>

              {/* Status */}
              <div className="col-span-2">
                {getStatusBadge(product.status || "INACTIVE")}
              </div>

              {/* Actions */}
              <div className="col-span-1">
                <div className="flex items-center space-x-2">
                  {/* Toggle Status Button */}
                  <button
                    onClick={() => onToggleStatus && onToggleStatus(product)}
                    className={`p-2 rounded-md transition-colors duration-200 ${product.status === PRODUCT_STATUS.DELETING || product.status === PRODUCT_STATUS.REMOVED || product.status === PRODUCT_STATUS.SOLD || toggleLoading === product.productId
                        ? 'text-gray-300 bg-gray-100 cursor-not-allowed'
                        : product.status === PRODUCT_STATUS.ACTIVE
                          ? 'text-green-600 bg-green-50 hover:bg-green-100 hover:text-green-700'
                          : 'text-orange-600 bg-orange-50 hover:bg-orange-100 hover:text-orange-700'
                      }`}
                    title={
                      toggleLoading === product.productId
                        ? 'Updating status...'
                        : product.status === PRODUCT_STATUS.DELETING
                          ? 'Cannot change status while deleting'
                          : product.status === PRODUCT_STATUS.REMOVED
                            ? 'Cannot change status of removed product'
                            : product.status === PRODUCT_STATUS.SOLD
                              ? 'Cannot change status of sold product'
                              : product.status === PRODUCT_STATUS.ACTIVE
                                ? 'Deactivate Product'
                                : 'Activate Product'
                    }
                    disabled={product.status === PRODUCT_STATUS.DELETING || product.status === PRODUCT_STATUS.REMOVED || product.status === PRODUCT_STATUS.SOLD || toggleLoading === product.productId}
                  >
                    {toggleLoading === product.productId ? (
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-gray-400"></div>
                    ) : product.status === PRODUCT_STATUS.ACTIVE ? (
                      <IoCheckmarkCircleOutline size={16} />
                    ) : (
                      <IoCloseCircleOutline size={16} />
                    )}
                  </button>

                  {/* Edit Button */}
                  <button
                    onClick={() => onEdit && onEdit(product)}
                    className={`p-2 rounded-md transition-colors duration-200 ${product.status === PRODUCT_STATUS.DELETING
                        ? 'text-gray-300 bg-gray-100 cursor-not-allowed'
                        : 'text-blue-600 bg-blue-50 hover:bg-blue-100 hover:text-blue-700'
                      }`}
                    title={product.status === PRODUCT_STATUS.DELETING ? 'Cannot edit while deleting' : 'Edit Product'}
                    disabled={product.status === PRODUCT_STATUS.DELETING}
                  >
                    <IoCreateOutline size={16} />
                  </button>

                  {/* Delete Button */}
                  <button
                    onClick={() => onDelete && onDelete(product)}
                    className={`p-2 rounded-md transition-colors duration-200 ${product.status === PRODUCT_STATUS.DELETING || product.status === PRODUCT_STATUS.REMOVED
                        ? 'text-gray-300 bg-gray-100 cursor-not-allowed'
                        : 'text-red-600 bg-red-50 hover:bg-red-100 hover:text-red-700'
                      }`}
                    title={
                      product.status === PRODUCT_STATUS.DELETING
                        ? 'Already deleting'
                        : product.status === PRODUCT_STATUS.REMOVED
                          ? 'Already removed'
                          : 'Delete Product'
                    }
                    disabled={product.status === PRODUCT_STATUS.DELETING || product.status === PRODUCT_STATUS.REMOVED}
                  >
                    <IoTrashOutline size={16} />
                  </button>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
