import axiosClient from "@/utils/axios.js";

const PRODUCT_API = {
  CREATE_PRODUCTS: '/api/products',
  UPLOAD_IMAGE: '/api/products/upload',
  MY_PRODUCTS: '/api/products/my-products',
  MY_ACTIVE_PRODUCTS: '/api/products/my-products/active',
  UPDATE_PRODUCTS: '/api/products',
  DELETE_PRODUCTS: '/api/products',
  GET_PRODUCT_BY_ID: '/api/products',
  EXPORT_PRODUCTS: '/api/products/export/excel',
};

export const productService = {
  // Upload product image
  uploadImage: async (file, fileName) => {
    try {
      const formData = new FormData();
      formData.append('image', file);
      // Only add fileName if it's provided and not empty
      if (fileName && fileName.trim()) {
        formData.append('fileName', fileName.trim());
      }

      const response = await axiosClient.post(
        PRODUCT_API.UPLOAD_IMAGE,
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        }
      );
      return response.data;
    } catch (err) {
      const statusCode = err?.status;
      const { message, code } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || 500,
        message: message || 'Image upload failed',
        errorCode: code || 'INTERNAL_SERVER_ERROR',
      });
    }
  },

  // Create multiple products
  createProducts: async (products) => {
    // Ensure stockQuantity is a number for each product
    const processedProducts = products.map(product => ({
      ...product,
      stockQuantity: typeof product.stockQuantity === 'string'
        ? parseInt(product.stockQuantity, 10)
        : product.stockQuantity,
      imageUrls: product.imageUrls || []
    }));

    try {
      const response = await axiosClient.post(
        PRODUCT_API.CREATE_PRODUCTS,
        { products: processedProducts }
      );
      return response.data;
    } catch (err) {
      const statusCode = err?.status;
      const { message, code } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || 500,
        message: message || 'Product creation failed',
        errorCode: code || 'INTERNAL_SERVER_ERROR',
      });
    }
  },

  // Get my products
  getMyProducts: async () => {
    try {
      const response = await axiosClient.get(PRODUCT_API.MY_PRODUCTS);
      return response.data;
    } catch (err) {
      const statusCode = err?.status;
      const { message, code } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || 500,
        message: message || 'Failed to fetch products',
        errorCode: code || 'INTERNAL_SERVER_ERROR',
      });
    }
  },

  // Get my active products (for auction creation)
  getMyActiveProducts: async () => {
    try {
      const response = await axiosClient.get(PRODUCT_API.MY_ACTIVE_PRODUCTS);
      return response.data;
    } catch (err) {
      const statusCode = err?.status;
      const { message, code } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || 500,
        message: message || 'Failed to fetch active products',
        errorCode: code || 'INTERNAL_SERVER_ERROR',
      });
    }
  },

  // Get product by ID
  getProductById: async (productId) => {
    try {
      const response = await axiosClient.get(`${PRODUCT_API.GET_PRODUCT_BY_ID}/${productId}`);
      return response.data;
    } catch (err) {
      const statusCode = err?.status;
      const { message, code } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || 500,
        message: message || 'Failed to fetch product',
        errorCode: code || 'INTERNAL_SERVER_ERROR',
      });
    }
  },

  // Update products
  updateProducts: async (products) => {
    // Ensure stockQuantity is a number for each product
    const processedProducts = products.map(product => ({
      ...product,
      stockQuantity: typeof product.stockQuantity === 'string'
        ? parseInt(product.stockQuantity, 10)
        : product.stockQuantity,
      imageUrls: product.imageUrls || []
    }));

    try {
      const response = await axiosClient.put(
        PRODUCT_API.UPDATE_PRODUCTS,
        { products: processedProducts }
      );
      return response.data;
    } catch (err) {
      const statusCode = err?.status;
      const { message, code } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || 500,
        message: message || 'Product update failed',
        errorCode: code || 'INTERNAL_SERVER_ERROR',
      });
    }
  },

  // Delete products
  deleteProducts: async (productIds) => {
    try {
      const idsString = productIds.join(',');
      const response = await axiosClient.delete(`${PRODUCT_API.DELETE_PRODUCTS}/${idsString}`);
      return response.data;
    } catch (err) {
      const statusCode = err?.status;
      const { message, code } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || 500,
        message: message || 'Product deletion failed',
        errorCode: code || 'INTERNAL_SERVER_ERROR',
      });
    }
  },

  // Export products to Excel
  exportProductsToExcel: async (params = {}) => {
    try {
      const queryParams = new URLSearchParams();

      // Add query parameters if provided
      if (params.status) {
        queryParams.append('status', params.status);
      }
      if (params.sellerId) {
        queryParams.append('sellerId', params.sellerId);
      }

      const response = await axiosClient.get(
        `${PRODUCT_API.EXPORT_PRODUCTS}?${queryParams.toString()}`,
        {
          responseType: 'blob', // Important for downloading files
        }
      );

      // Create blob and download file
      const blob = new Blob([response.data], {
        type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      });

      // Get filename from response headers or create default
      const contentDisposition = response.headers['content-disposition'];
      let filename = 'products_export.xlsx';

      if (contentDisposition) {
        const matches = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/.exec(contentDisposition);
        if (matches != null && matches[1]) {
          filename = matches[1].replace(/['"]/g, '');
        }
      }

      // Create download link
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;

      // Trigger download
      document.body.appendChild(link);
      link.click();

      // Cleanup
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      return { success: true, filename };
    } catch (err) {
      const statusCode = err?.status;
      const { message, code } = err?.response?.data || {};
      return Promise.reject({
        statusCode: statusCode || 500,
        message: message || 'Export failed',
        errorCode: code || 'INTERNAL_SERVER_ERROR',
      });
    }
  }
};
