/**
 * Get the primary image URL from a product's images array
 * @param {Array} images - Array of image objects with imageUrl and isPrimary properties
 * @returns {string|null} - The image URL or null if no images
 */
export const getPrimaryImageUrl = (images) => {
  if (!images || !Array.isArray(images) || images.length === 0) {
    return null;
  }
  
  // Find primary image first
  const primaryImage = images.find(img => img.isPrimary);
  if (primaryImage && primaryImage.imageUrl) {
    return validateImageUrl(primaryImage.imageUrl);
  }
  
  // Fallback to first image if no primary
  const firstImage = images[0];
  return firstImage && firstImage.imageUrl ? validateImageUrl(firstImage.imageUrl) : null;
};

/**
 * Validate and fix image URL if needed
 * @param {string} imageUrl - The image URL to validate
 * @returns {string|null} - The validated image URL or null
 */
export const validateImageUrl = (imageUrl) => {
  if (!imageUrl || typeof imageUrl !== 'string') {
    return null;
  }
  
  // If URL is already absolute, return as is
  if (imageUrl.startsWith('http://') || imageUrl.startsWith('https://')) {
    return imageUrl;
  }
  
  // If URL starts with '/', prepend base URL
  if (imageUrl.startsWith('/')) {
    const baseUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:3000';
    return `${baseUrl}${imageUrl}`;
  }
  
  // If it's a relative path, prepend full base URL
  const baseUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:3000';
  return `${baseUrl}/${imageUrl}`;
};

/**
 * Get product information including image URL from order data
 * @param {Object} order - Order object containing auction and product data
 * @returns {Object} - Object with name and image properties
 */
export const getOrderProductInfo = (order) => {
  if (!order.auction?.auctionProducts || order.auction.auctionProducts.length === 0) {
    return { name: "N/A", image: null };
  }
  
  const product = order.auction.auctionProducts[0].product;
  const imageUrl = getPrimaryImageUrl(product.images);
  
  return {
    name: product.name || "N/A",
    image: imageUrl
  };
};

/**
 * Handle image load error by hiding the image and showing fallback
 * @param {Event} e - The error event
 * @param {Function} fallbackAction - Optional callback for additional error handling
 */
export const handleImageError = (e, fallbackAction) => {
  e.target.style.display = 'none';
  
  // Look for the fallback element (next sibling or within the same parent)
  const parent = e.target.parentElement;
  const fallbackElement = parent.querySelector('[style*="display: none"]');
  
  if (fallbackElement) {
    fallbackElement.style.display = 'flex';
  }
  
  if (fallbackAction && typeof fallbackAction === 'function') {
    fallbackAction(e);
  }
};