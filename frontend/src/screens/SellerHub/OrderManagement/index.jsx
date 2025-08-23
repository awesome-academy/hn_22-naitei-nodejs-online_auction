import React, { useState, useEffect, useCallback } from "react";
import { Title } from "@/components/ui/index.js";
import { orderService } from "@/services/order.service";
import SellerOrderTable from "./components/SellerOrderTable";
import SellerOrderCard from "./components/SellerOrderCard";
import SellerOrderFilters from "./components/SellerOrderFilters";
import SellerOrderDetailsModal from "./components/SellerOrderDetailsModal";
import ConfirmShippedModal from "./components/ConfirmShippedModal";
import Pagination from "@/components/ui/Pagination";

const SellerOrderManagement = () => {
  const [orders, setOrders] = useState([]);
  const [filteredOrders, setFilteredOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Modal states
  const [detailsModal, setDetailsModal] = useState({ isOpen: false, order: null });
  const [confirmShippedModal, setConfirmShippedModal] = useState({ isOpen: false, order: null });
  const [successMessage, setSuccessMessage] = useState("");

  // Pagination state
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 10,
    total: 0,
    totalPages: 0,
    hasNext: false,
    hasPrevious: false,
  });

  // Filter states
  const [searchTerm, setSearchTerm] = useState("");
  const [period, setPeriod] = useState("");
  const [searchBy, setSearchBy] = useState("auction_title");
  const [sortBy, setSortBy] = useState("createdAt");
  const [sortOrder, setSortOrder] = useState("desc");
  const [statusFilter, setStatusFilter] = useState("");

  // Fetch orders from API
  const fetchOrders = useCallback(async (page = 1, limit = 10) => {
    try {
      setLoading(true);
      setError("");

      const response = await orderService.getOrders({
        page,
        limit,
        status: statusFilter || undefined,
        search: searchTerm || undefined,
        sortBy: sortBy,
        sortOrder: sortOrder,
      });

      setOrders(response.orders || []);
      setPagination({
        page: response.pagination.currentPage,
        limit: response.pagination.itemsPerPage,
        total: response.pagination.totalItems,
        totalPages: response.pagination.totalPages,
        hasNext: response.pagination.hasNextPage,
        hasPrevious: response.pagination.hasPreviousPage,
      });
    } catch (error) {
      console.error("Error fetching orders:", error);
      setError(error.message || "Failed to fetch orders");
      setOrders([]);
    } finally {
      setLoading(false);
    }
  }, [searchTerm, sortBy, sortOrder, statusFilter]);

  // Filter and sort logic
  const filterAndSortOrders = useCallback(() => {
    let filtered = [...orders];

    // Apply search filter based on searchBy criteria
    if (searchTerm) {
      filtered = filtered.filter((order) => {
        switch (searchBy) {
          case "auction_title":
            return order.auction?.title?.toLowerCase().includes(searchTerm.toLowerCase());
          case "order_id":
            return order.orderId?.toLowerCase().includes(searchTerm.toLowerCase());
          case "buyer_name":
            return order.user?.profile?.fullName?.toLowerCase().includes(searchTerm.toLowerCase());
          case "buyer_email":
            return order.user?.email?.toLowerCase().includes(searchTerm.toLowerCase());
          default:
            return true;
        }
      });
    }

    // Apply period filter
    if (period) {
      const now = new Date();
      let startDate = new Date();

      switch (period) {
        case "today":
          startDate.setHours(0, 0, 0, 0);
          break;
        case "7_days":
          startDate.setDate(now.getDate() - 7);
          break;
        case "30_days":
          startDate.setDate(now.getDate() - 30);
          break;
        case "90_days":
          startDate.setDate(now.getDate() - 90);
          break;
        default:
          startDate = null;
          break;
      }

      if (startDate) {
        filtered = filtered.filter(order => new Date(order.createdAt) >= startDate);
      }
    }

    setFilteredOrders(filtered);
  }, [orders, searchTerm, searchBy, period]);

  // Initialize data
  useEffect(() => {
    fetchOrders();
  }, [fetchOrders]);

  // Apply filters when dependencies change
  useEffect(() => {
    filterAndSortOrders();
  }, [filterAndSortOrders]);

  // Handle pagination change
  const handlePageChange = (newPage) => {
    fetchOrders(newPage, pagination.limit);
  };

  const handleViewDetails = (order) => {
    setDetailsModal({ isOpen: true, order });
  };

  const handleConfirmShipped = (order) => {
    setConfirmShippedModal({ isOpen: true, order });
  };

  const handleConfirmShippedSuccess = (orderId, newStatus) => {
    // Update the order status in the current orders list
    setOrders(prevOrders => 
      prevOrders.map(order => 
        order.orderId === orderId 
          ? { ...order, status: newStatus }
          : order
      )
    );
    
    // Show success message
    setSuccessMessage("Order has been successfully marked as shipped!");
    
    // Clear success message after 5 seconds
    setTimeout(() => {
      setSuccessMessage("");
    }, 5000);
  };

  const handleSortChange = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(field);
      setSortOrder("desc");
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'PENDING':
        return 'bg-yellow-100 text-yellow-800';
      case 'PAID':
        return 'bg-blue-100 text-blue-800';
      case 'SHIPPING':
        return 'bg-purple-100 text-purple-800';
      case 'COMPLETED':
        return 'bg-green-100 text-green-800';
      case 'CANCELED':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: 'VND',
    }).format(amount);
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('vi-VN', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <Title level={2} className="text-3xl font-bold text-gray-900">
            Order Management
          </Title>

          <div className="flex items-center gap-4">
            <div className="text-sm text-gray-600">
              Total: {pagination.total} orders
            </div>
            <button 
              onClick={() => fetchOrders(pagination.page, pagination.limit)}
              className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg flex items-center gap-2 transition-colors duration-200"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              Refresh
            </button>
          </div>
        </div>

      {/* Filters */}
      <SellerOrderFilters
        searchTerm={searchTerm}
        setSearchTerm={setSearchTerm}
        period={period}
        setPeriod={setPeriod}
        searchBy={searchBy}
        setSearchBy={setSearchBy}
        sortBy={sortBy}
        setSortBy={setSortBy}
        sortOrder={sortOrder}
        setSortOrder={setSortOrder}
        statusFilter={statusFilter}
        setStatusFilter={setStatusFilter}
      />

      {/* Success Message */}
      {successMessage && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
          <div className="flex items-center">
            <svg className="w-4 h-4 text-green-600 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <p className="text-green-800">{successMessage}</p>
          </div>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
          <p className="text-red-800">{error}</p>
        </div>
      )}

      {/* Orders Table - Desktop View */}
      <div className="hidden lg:block">
        <SellerOrderTable
          orders={filteredOrders}
          loading={loading}
          onViewDetails={handleViewDetails}
          onConfirmShipped={handleConfirmShipped}
          sortBy={sortBy}
          sortOrder={sortOrder}
          onSortChange={handleSortChange}
          getStatusColor={getStatusColor}
          formatCurrency={formatCurrency}
        />
      </div>

      {/* Orders Grid - Mobile & Tablet View */}
      <div className="lg:hidden">
        {loading ? (
          <div className="bg-white border border-gray-200 rounded-lg p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-600 mx-auto"></div>
            <p className="mt-2 text-gray-600">Loading orders...</p>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-1 md:grid-cols-2">
            {filteredOrders.map((order) => (
              <SellerOrderCard
                key={order.orderId}
                order={order}
                onViewDetails={handleViewDetails}
                onConfirmShipped={handleConfirmShipped}
                getStatusColor={getStatusColor}
                formatCurrency={formatCurrency}
              />
            ))}
          </div>
        )}
      </div>

      {/* Pagination */}
      {filteredOrders.length > 0 && (
        <Pagination
          currentPage={pagination.page}
          totalPages={pagination.totalPages}
          hasNext={pagination.hasNext}
          hasPrevious={pagination.hasPrevious}
          onPageChange={handlePageChange}
          totalItems={pagination.total}
          limit={pagination.limit}
        />
      )}

      {/* Empty State */}
      {!loading && filteredOrders.length === 0 && (
        <div className="text-center py-12">
          <Title level={3} className="text-xl font-medium text-gray-900 mb-2">
            No orders found
          </Title>
          <p className="text-gray-600 mb-6">
            {searchTerm ? "Try adjusting your search criteria" : "Orders will appear here when customers purchase your auction items"}
          </p>
        </div>
      )}

      {/* Order Details Modal */}
      <SellerOrderDetailsModal
        isOpen={detailsModal.isOpen}
        onClose={() => setDetailsModal({ isOpen: false, order: null })}
        order={detailsModal.order}
        getStatusColor={getStatusColor}
        formatCurrency={formatCurrency}
        formatDate={formatDate}
      />

      {/* Confirm Shipped Modal */}
      <ConfirmShippedModal
        isOpen={confirmShippedModal.isOpen}
        onClose={() => setConfirmShippedModal({ isOpen: false, order: null })}
        order={confirmShippedModal.order}
        onSuccess={handleConfirmShippedSuccess}
        formatCurrency={formatCurrency}
      />
    </div>
    </div>
  );
};

export default SellerOrderManagement;
