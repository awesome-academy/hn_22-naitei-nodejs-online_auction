import axiosClient from "@/utils/axios.js";

const PRODUCT_API = {
  CREATE_PRODUCTS: '/api/products',
  UPLOAD_IMAGE: '/api/products/upload',
  MY_PRODUCTS: '/api/products/my-products',
  MY_ACTIVE_PRODUCTS: '/api/products/my-products/active',
  UPDATE_PRODUCTS: '/api/products',
  DELETE_PRODUCTS: '/api/products',
  GET_PRODUCT_BY_ID: '/api/products',
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
  }
};
