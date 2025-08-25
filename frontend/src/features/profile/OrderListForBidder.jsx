import React, { useState, useEffect, useCallback } from "react";
import { useUser } from "@/contexts/UserContext.jsx";
import { useNotification } from "@/contexts/NotificationContext.jsx";
import { orderService } from "@/services/order.service.js";
import { ORDER_STATUS, ORDER_STATUS_LABELS, ORDER_STATUS_COLORS } from "@/constants/orderStatus.js";
import { formatVND, formatDate } from "@/utils/format.js";
import { getOrderProductInfo, handleImageError } from "@/utils/imageUtils.js";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { Pagination } from "@/components/ui/index.js";
import OrderDetailModal from "@/components/ui/OrderDetailModal.jsx";
import { 
  IoSearchOutline, 
  IoChevronDownOutline, 
  IoEyeOutline,
  IoReceiptOutline,
  IoTimeOutline,
  IoCheckmarkCircleOutline,
  IoCloseCircleOutline,
  IoCardOutline,
  IoImageOutline,
  IoWalletOutline,
  IoFlashOutline,
  IoLockClosedOutline
} from "react-icons/io5";

const OrderListForBidder = () => {
  const { user } = useUser();
  const { showNotification } = useNotification();
  
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  
  // Filters and pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [sortBy, setSortBy] = useState("createdAt");
  const [sortOrder, setSortOrder] = useState("desc");
  
  // Modal state
  const [selectedOrder, setSelectedOrder] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  
  const limit = 10;

  const fetchOrders = useCallback(async () => {
    try {
      setLoading(true);
      setError("");
      
      const params = {
        page: currentPage,
        limit,
        status: statusFilter,
        sortBy,
        sortOrder,
        search: searchTerm
      };

      const response = await orderService.getOrders(params);
      
      setOrders(response.orders || []);
      setTotalPages(response.pagination?.totalPages || 1);
      setTotalItems(response.pagination?.totalItems || 0);
      
    } catch (err) {
      setError(err.message || "Failed to fetch orders");
      showNotification("Failed to fetch orders", "error");
    } finally {
      setLoading(false);
    }
  }, [currentPage, statusFilter, sortBy, sortOrder, searchTerm, showNotification]);

  useEffect(() => {
    if (user?.role === "BIDDER") {
      fetchOrders();
    }
  }, [user, currentPage, statusFilter, sortBy, sortOrder, searchTerm, fetchOrders]);

  const handleSearch = (e) => {
    e.preventDefault();
    setCurrentPage(1);
    fetchOrders();
  };

  const handleStatusFilter = (status) => {
    setStatusFilter(status);
    setCurrentPage(1);
  };

  const handleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(field);
      setSortOrder("desc");
    }
    setCurrentPage(1);
  };

  const handleViewDetails = (order) => {
    setSelectedOrder(order);
    setIsModalOpen(true);
  };

  const handleCloseModal = () => {
    setIsModalOpen(false);
    setSelectedOrder(null);
  };

  const handlePayOrder = async (order) => {
    try {
      // TODO: Implement payment logic
      console.log("Processing payment for order:", order.orderId);
      showNotification("Coming soon", "info");
    } catch (error) {
      showNotification("Payment failed: " + error.message, "error");
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case ORDER_STATUS.PENDING:
        return <IoTimeOutline className="w-4 h-4" />;
      case ORDER_STATUS.PAID:
        return <IoReceiptOutline className="w-4 h-4" />;
      case ORDER_STATUS.SHIPPING:
        return <IoReceiptOutline className="w-4 h-4" />;
      case ORDER_STATUS.COMPLETED:
        return <IoCheckmarkCircleOutline className="w-4 h-4" />;
      case ORDER_STATUS.CANCELED:
        return <IoCloseCircleOutline className="w-4 h-4" />;
      default:
        return <IoReceiptOutline className="w-4 h-4" />;
    }
  };

  if (user?.role !== "BIDDER") {
    return (
      <div className="text-center py-8">
        <p className="text-gray-600">This section is only available for bidders.</p>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">My Orders</h1>
        <p className="text-gray-600">Track and manage your auction orders</p>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex flex-col lg:flex-row gap-4 items-start lg:items-center justify-between">
          {/* Search */}
          <form onSubmit={handleSearch} className="flex-1 max-w-md">
            <div className="relative">
              <input
                type="text"
                placeholder="Search by auction title or order ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500"
              />
              <IoSearchOutline className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={16} />
            </div>
          </form>

          {/* Status Filter */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-700">Status:</span>
              <div className="relative">
                <select
                  value={statusFilter}
                  onChange={(e) => handleStatusFilter(e.target.value)}
                  className="appearance-none bg-white border border-gray-300 rounded-lg px-3 py-2.5 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 min-w-[140px]"
                >
                  <option value="">All Status</option>
                  {Object.values(ORDER_STATUS).map((status) => (
                    <option key={status} value={status}>
                      {ORDER_STATUS_LABELS[status]}
                    </option>
                  ))}
                </select>
                <IoChevronDownOutline className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400" size={14} />
              </div>
            </div>

            {/* Sort */}
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-700">Sort:</span>
              <div className="relative">
                <select
                  value={`${sortBy}-${sortOrder}`}
                  onChange={(e) => {
                    const [field, order] = e.target.value.split('-');
                    setSortBy(field);
                    setSortOrder(order);
                    setCurrentPage(1);
                  }}
                  className="appearance-none bg-white border border-gray-300 rounded-lg px-3 py-2.5 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 min-w-[160px]"
                >
                  <option value="createdAt-desc">Newest First</option>
                  <option value="createdAt-asc">Oldest First</option>
                  <option value="totalAmount-desc">Price High to Low</option>
                  <option value="totalAmount-asc">Price Low to High</option>
                </select>
                <IoChevronDownOutline className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400" size={14} />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Results Info */}
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-gray-600">
          Showing {orders.length} of {totalItems} orders
        </p>
      </div>

      {/* Orders Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner />
          </div>
        ) : error ? (
          <div className="text-center py-12">
            <p className="text-red-600">{error}</p>
            <button
              onClick={fetchOrders}
              className="mt-4 px-4 py-2 bg-green text-white rounded-lg hover:bg-green-600 transition-colors"
            >
              Try Again
            </button>
          </div>
        ) : orders.length === 0 ? (
          <div className="text-center py-12">
            <IoReceiptOutline className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-600 text-lg font-medium mb-2">No orders found</p>
            <p className="text-gray-500">
              {searchTerm || statusFilter 
                ? "Try adjusting your search or filter criteria"
                : "You haven't placed any orders yet"
              }
            </p>
          </div>
        ) : (
          <>
            {/* Desktop Table */}
            <div className="hidden lg:block overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Order
                    </th>
                    <th 
                      className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                      onClick={() => handleSort('totalAmount')}
                    >
                      Total Amount
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th 
                      className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                      onClick={() => handleSort('createdAt')}
                    >
                      Order Date
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {orders.map((order) => {
                    const productInfo = getOrderProductInfo(order);
                    
                    return (
                    <tr key={order.orderId} className="hover:bg-gray-50">
                      <td className="px-6 py-4">
                        <div className="flex items-start gap-4">
                          {/* Product Image */}
                          <div className="w-20 h-20 rounded-lg overflow-hidden bg-gray-100 flex-shrink-0 border border-gray-200">
                            {productInfo.image ? (
                              <img 
                                src={productInfo.image} 
                                alt={productInfo.name || "Product"}
                                className="w-full h-full object-cover"
                                onError={(e) => handleImageError(e)}
                              />
                            ) : (
                              <div className="w-full h-full flex items-center justify-center text-gray-400">
                                <IoImageOutline className="w-8 h-8" />
                              </div>
                            )}
                          </div>
                          
                          <div className="min-w-0 flex-1">
                            <div className="text-sm font-medium text-gray-900 mb-1">
                              {order.auction?.title || "Unknown Auction"}
                            </div>
                            <div className="text-sm text-gray-600 mb-1">
                              {productInfo.name}
                            </div>
                            {order.auction?.seller?.profile?.fullName && (
                              <div className="text-xs text-gray-500">
                                Seller: {order.auction.seller.profile.fullName}
                              </div>
                            )}
                            <div className="text-xs text-gray-400 mt-1">
                              Order #{order.orderId.slice(-8)}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm font-semibold text-gray-900">
                          {formatVND(order.totalAmount)}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-full text-xs font-medium ${ORDER_STATUS_COLORS[order.status]}`}>
                          {getStatusIcon(order.status)}
                          {ORDER_STATUS_LABELS[order.status]}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-gray-900">
                          {formatDate(order.createdAt)}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <button 
                            onClick={() => handleViewDetails(order)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-green border border-green rounded-lg hover:bg-green hover:text-white transition-colors"
                          >
                            <IoEyeOutline className="w-4 h-4" />
                            Details
                          </button>
                          {order.status === ORDER_STATUS.PENDING && (
                            <button 
                              onClick={() => handlePayOrder(order)}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-green border border-green rounded-lg hover:bg-green-600 transition-colors"
                            >
                              <IoCardOutline className="w-4 h-4" />
                              Pay Now
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Mobile Cards */}
            <div className="lg:hidden">
              {orders.map((order) => {
                const productInfo = getOrderProductInfo(order);
                
                return (
                <div key={order.orderId} className="border-b border-gray-200 p-4 last:border-b-0">
                  <div className="space-y-4">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="text-sm font-medium text-gray-900">
                          Order #{order.orderId.slice(-8)}
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
                          {formatDate(order.createdAt)}
                        </div>
                      </div>
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-full text-xs font-medium ${ORDER_STATUS_COLORS[order.status]}`}>
                        {getStatusIcon(order.status)}
                        {ORDER_STATUS_LABELS[order.status]}
                      </span>
                    </div>

                    <div className="flex items-start gap-4">
                      {/* Product Image */}
                      <div className="w-20 h-20 rounded-lg overflow-hidden bg-gray-100 flex-shrink-0 border border-gray-200">
                        {productInfo.image ? (
                          <img 
                            src={productInfo.image} 
                            alt={productInfo.name || "Product"}
                            className="w-full h-full object-cover"
                            onError={(e) => handleImageError(e)}
                          />
                        ) : (
                          <div className="w-full h-full flex items-center justify-center text-gray-400">
                            <IoImageOutline className="w-6 h-6" />
                          </div>
                        )}
                      </div>

                      {/* Product Info */}
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium text-gray-900">
                          {order.auction?.title || "Unknown Auction"}
                        </div>
                        <div className="text-sm text-gray-600">
                          {productInfo.name}
                        </div>
                        {order.auction?.seller?.profile?.fullName && (
                          <div className="text-xs text-gray-500 mt-1">
                            Seller: {order.auction.seller.profile.fullName}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="text-lg font-semibold text-gray-900">
                        {formatVND(order.totalAmount)}
                      </div>
                      <div className="flex items-center gap-2">
                        <button 
                          onClick={() => handleViewDetails(order)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-green border border-green rounded-lg hover:bg-green hover:text-white transition-colors"
                        >
                          <IoEyeOutline className="w-4 h-4" />
                          Details
                        </button>
                        {order.status === ORDER_STATUS.PENDING && (
                          <button 
                            onClick={() => handlePayOrder(order)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-green border border-green rounded-lg hover:bg-green-600 transition-colors"
                          >
                            <IoCardOutline className="w-4 h-4" />
                            Pay
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
                );
              })}
            </div>
          </>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="mt-6">
          <Pagination
            currentPage={currentPage}
            totalPages={totalPages}
            hasNext={currentPage < totalPages}
            hasPrevious={currentPage > 1}
            onPageChange={setCurrentPage}
            totalItems={totalItems}
            limit={limit}
          />
        </div>
      )}

      {/* Order Detail Modal */}
      <OrderDetailModal
        order={selectedOrder}
        isOpen={isModalOpen}
        onClose={handleCloseModal}
      />
    </div>
  );
};

export default OrderListForBidder;
