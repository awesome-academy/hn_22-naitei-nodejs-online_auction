import { useState } from "react";
import { useNotification } from "@/contexts/NotificationContext.jsx";
import { useNavigate } from "react-router-dom";
import { productService } from "@/services/product.service.js";

export const useAddMultipleProducts = () => {
  const [products, setProducts] = useState([{
    productName: "",
    description: "",
    stockQuantity: "",
    uploadedImages: [],
  }]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(null); // null hoặc index của product đang upload

  const { showToastNotification } = useNotification();
  const navigate = useNavigate();

  const addProduct = () => {
    setProducts(prev => [...prev, {
      productName: "",
      description: "",
      stockQuantity: "",
      uploadedImages: [],
    }]);
  };

  const importProductsFromExcel = (importedProducts) => {
    if (!importedProducts || importedProducts.length === 0) {
      setError("Không có dữ liệu để import");
      return;
    }

    // Merge với products hiện tại, loại bỏ products trống
    const currentProducts = products.filter(p =>
      p.productName.trim() || p.description.trim() || p.stockQuantity || p.uploadedImages.length > 0
    );

    const newProducts = [...currentProducts, ...importedProducts];

    // Giới hạn tối đa 100 products
    if (newProducts.length > 100) {
      setError(`Không thể tạo quá 100 sản phẩm cùng lúc. Hiện tại có ${currentProducts.length} sản phẩm, import thêm ${importedProducts.length} sẽ vượt quá giới hạn.`);
      return;
    }

    setProducts(newProducts);
    setError("");
    showToastNotification(`Đã import ${importedProducts.length} sản phẩm từ Excel`, 'success');
  };

  const clearAllProducts = () => {
    setProducts([{
      productName: "",
      description: "",
      stockQuantity: "",
      uploadedImages: [],
    }]);
    setError("");
  };

  const removeProduct = (index) => {
    if (products.length > 1) {
      setProducts(prev => prev.filter((_, i) => i !== index));
    }
  };

  const updateProduct = (index, field, value) => {
    setProducts(prev => prev.map((product, i) =>
      i === index ? { ...product, [field]: value } : product
    ));
  };

  const handleImageUpload = async (file, productIndex) => {
    if (!file) return null;

    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (!allowedTypes.includes(file.type)) {
      setError('Only image files (JPEG, PNG, WebP, GIF) are allowed');
      return null;
    }

    // Validate file size (max 5MB)
    const maxSize = 5 * 1024 * 1024;
    if (file.size > maxSize) {
      setError('File size must be less than 5MB');
      return null;
    }

    setUploading(productIndex);
    setError("");

    try {
      const response = await productService.uploadImage(file, file.name);
      const imageUrl = response.imageUrl;

      setProducts(prev => prev.map((product, i) =>
        i === productIndex
          ? { ...product, uploadedImages: [...product.uploadedImages, imageUrl] }
          : product
      ));

      showToastNotification('Image uploaded successfully!', 'success');
      return imageUrl;
    } catch (err) {
      console.error('Image upload error:', err);
      setError(err.message || 'Image upload failed');
      showToastNotification(err.message || 'Image upload failed', 'error');
      return null;
    } finally {
      setUploading(null);
    }
  };

  const removeImage = (productIndex, imageIndex) => {
    setProducts(prev => prev.map((product, i) =>
      i === productIndex
        ? { ...product, uploadedImages: product.uploadedImages.filter((_, imgI) => imgI !== imageIndex) }
        : product
    ));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    // Validation
    for (let i = 0; i < products.length; i++) {
      const product = products[i];

      if (!product.productName.trim()) {
        setError(`Product ${i + 1} name is required`);
        setLoading(false);
        return;
      }

      if (!product.stockQuantity || parseInt(product.stockQuantity) < 0) {
        setError(`Product ${i + 1} stock quantity must be a positive number`);
        setLoading(false);
        return;
      }
    }

    try {
      const productsData = products.map(product => ({
        name: product.productName.trim(),
        description: product.description.trim() || undefined,
        stockQuantity: parseInt(product.stockQuantity),
        imageUrls: product.uploadedImages,
      }));

      const response = await productService.createProducts(productsData);

      if (response?.products && response.products.length > 0) {
        showToastNotification(`${response.products.length} products created successfully!`, 'success');

        // Reset form
        setProducts([{
          productName: "",
          description: "",
          stockQuantity: "",
          uploadedImages: [],
        }]);

        navigate('/seller-hub/listings/product');
      }
    } catch (err) {
      console.error('Products creation error:', err);
      setError(err.message || 'Products creation failed');
      showToastNotification(err.message || 'Products creation failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  return {
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
    loading,
    uploading,
  };
};
