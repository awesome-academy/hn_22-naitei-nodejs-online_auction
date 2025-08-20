import React, { useState, useEffect, useCallback } from "react";
import { useUser } from "@/contexts/UserContext.jsx";
import { useNotification } from "@/contexts/NotificationContext.jsx";
import { shippingService } from "@/services/shipping.service.js";
import { SHIPPING_STATUS, SHIPPING_STATUS_LABELS, SHIPPING_STATUS_COLORS, SHIPPING_SORT_OPTIONS } from "@/constants/shippingStatus.js";
import { formatVND, formatDate } from "@/utils/format.js";
import { LoadingSpinner } from "@/components/ui/LoadingSpinner";
import { Pagination } from "@/components/ui/index.js";
import ShippingDetailModal from "@/components/ui/ShippingDetailModal.jsx";
import ConfirmDeliveryModal from "@/components/ui/ConfirmDeliveryModal.jsx";
import { 
  IoSearchOutline, 
  IoChevronDownOutline, 
  IoEyeOutline,
  IoCarOutline,
  IoTimeOutline,
  IoCheckmarkCircleOutline,
  IoCloseCircleOutline,
  IoBusinessOutline,
  IoImageOutline,
  IoCalendarOutline,
  IoCodeWorkingOutline,
  IoSpeedometerOutline,
  IoShieldCheckmarkOutline,
  IoRefreshOutline
} from "react-icons/io5";

const ShippingListForBidder = () => {
  const { user } = useUser();
  const { showNotification } = useNotification();
  
  const [shippings, setShippings] = useState([]);
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
  const [selectedShipping, setSelectedShipping] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [confirmDeliveryModal, setConfirmDeliveryModal] = useState({
    isOpen: false,
    shippingId: null,
    auctionTitle: '',
  });
  const [confirmDeliveryLoading, setConfirmDeliveryLoading] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0); // To force re-render
  const [recentlyConfirmed, setRecentlyConfirmed] = useState(null); // Track recently confirmed shipping
  
  const limit = 10;

  const fetchShippings = useCallback(async (silent = false) => {
    try {
      if (!silent) {
        setLoading(true);
      }
      setError("");
      
      const params = {
        page: currentPage,
        limit,
        status: statusFilter,
        sortBy,
        sortOrder,
        search: searchTerm
      };

      const response = await shippingService.getBidderShippings(params);
      
      if (!silent) {
        console.log('Fetched shippings:', response.shippings);
      }
      
      setShippings(response.shippings || []);
      setTotalPages(response.pagination?.totalPages || 1);
      setTotalItems(response.pagination?.totalItems || 0);
      
    } catch (err) {
      setError(err.message || "Failed to fetch shippings");
      if (!silent) {
        showNotification("Failed to fetch shippings", "error");
      }
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  }, [currentPage, statusFilter, sortBy, sortOrder, searchTerm, showNotification]);

  useEffect(() => {
    if (user?.role === "BIDDER") {
      fetchShippings();
    }
  }, [user, currentPage, statusFilter, sortBy, sortOrder, searchTerm, fetchShippings, refreshKey]);

  // Auto-refresh data every 30 seconds to ensure real-time updates
  useEffect(() => {
    if (user?.role === "BIDDER") {
      const interval = setInterval(() => {
        fetchShippings(true); // Silent refresh
      }, 30000); // Refresh every 30 seconds

      return () => clearInterval(interval);
    }
  }, [user, fetchShippings]);

  // Debug: Log when shippings state changes
  useEffect(() => {
    console.log('Shippings state updated:', shippings.map(s => ({ id: s.id, status: s.shippingStatus })));
  }, [shippings]);

  const handleSearch = useCallback((e) => {
    e.preventDefault();
    setCurrentPage(1);
  }, []);

  const handleStatusFilter = useCallback((status) => {
    setStatusFilter(status);
    setCurrentPage(1);
  }, []);

  const handleSort = useCallback((field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(field);
      setSortOrder("desc");
    }
    setCurrentPage(1);
  }, [sortBy, sortOrder]);

  const handlePageChange = useCallback((page) => {
    setCurrentPage(page);
  }, []);

  const openShippingDetail = useCallback((shipping) => {
    setSelectedShipping(shipping);
    setIsModalOpen(true);
  }, []);

  const closeShippingDetail = useCallback(() => {
    setSelectedShipping(null);
    setIsModalOpen(false);
  }, []);

  const openConfirmDeliveryModal = useCallback((shipping) => {
    setConfirmDeliveryModal({
      isOpen: true,
      shippingId: shipping.id,
      auctionTitle: shipping.auction?.title || 'Unknown Auction',
    });
  }, []);

  const closeConfirmDeliveryModal = useCallback(() => {
    setConfirmDeliveryModal({
      isOpen: false,
      shippingId: null,
      auctionTitle: '',
    });
  }, []);

  const handleConfirmDelivery = useCallback(async () => {
    if (!confirmDeliveryModal.shippingId) return;
    
    try {
      setConfirmDeliveryLoading(true);
      console.log('Confirming delivery for shipping ID:', confirmDeliveryModal.shippingId);
      
      const response = await shippingService.confirmDelivery(confirmDeliveryModal.shippingId);
      console.log('Confirm delivery response:', response);
      
      // Show success notification
      showNotification(response.message || "Delivery confirmed successfully!", "success");
      
      // Close the confirmation modal immediately
      closeConfirmDeliveryModal();
      
      // Force refresh data from server silently to ensure consistency
      console.log('Refreshing shipping data after confirm delivery...');
      await fetchShippings(true);
      
      // Force component re-render
      setRefreshKey(prev => prev + 1);
      
      // Mark as recently confirmed
      setRecentlyConfirmed(confirmDeliveryModal.shippingId);
      
      // Clear the recently confirmed after 3 seconds
      setTimeout(() => {
        setRecentlyConfirmed(null);
      }, 3000);
      
      console.log('Shipping data refreshed successfully');
      
      // Also update selectedShipping if it's the same item and close detail modal
      if (selectedShipping && selectedShipping.id === confirmDeliveryModal.shippingId) {
        // Close the detail modal after a short delay to show the updated status
        setTimeout(() => {
          closeShippingDetail();
        }, 500);
      }
      
    } catch (err) {
      console.error("Error confirming delivery:", err);
      showNotification(err.message || "Failed to confirm delivery", "error");
    } finally {
      setConfirmDeliveryLoading(false);
    }
  }, [confirmDeliveryModal.shippingId, showNotification, closeConfirmDeliveryModal, selectedShipping, closeShippingDetail, fetchShippings]);

  const getStatusIcon = (status) => {
    switch (status) {
      case SHIPPING_STATUS.PENDING:
        return IoTimeOutline;
      case SHIPPING_STATUS.SHIPPED:
        return IoShieldCheckmarkOutline;
      case SHIPPING_STATUS.IN_TRANSIT:
        return IoSpeedometerOutline;
      case SHIPPING_STATUS.DELIVERED:
        return IoCheckmarkCircleOutline;
      default:
        return IoCarOutline;
    }
  };

  if (!user || user.role !== "BIDDER") {
    return (
      <div className="p-6 text-center">
        <p className="text-gray-500">Access denied. This page is only available for bidders.</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto p-6">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">My Shipments</h1>
              <p className="text-gray-600">Track your auction deliveries and shipping information</p>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
          <div className="flex flex-col lg:flex-row gap-4 items-start lg:items-center justify-between">
            {/* Search and Refresh */}
            <div className="flex gap-2 flex-1 max-w-md">
              <form onSubmit={handleSearch} className="flex-1">
                <div className="relative">
                  <input
                    type="text"
                    placeholder="Search by auction title, product name, or tracking number..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-12 pr-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 bg-gray-50 focus:bg-white transition-colors"
                  />
                  <IoSearchOutline className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
                </div>
              </form>
              <button
                onClick={() => fetchShippings()}
                disabled={loading}
                className="px-4 py-3 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                title="Refresh data"
              >
                <IoRefreshOutline className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              </button>
            </div>

            {/* Status Filter */}
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-gray-700">Status:</span>
                <div className="relative">
                  <select
                    value={statusFilter}
                    onChange={(e) => handleStatusFilter(e.target.value)}
                    className="appearance-none bg-white border border-gray-300 rounded-xl px-4 py-3 pr-10 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 min-w-[140px]"
                  >
                    <option value="">All Status</option>
                    {Object.entries(SHIPPING_STATUS_LABELS).map(([status, label]) => (
                      <option key={status} value={status}>
                        {label}
                      </option>
                    ))}
                  </select>
                  <IoChevronDownOutline className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={14} />
                </div>
              </div>

              {/* Sort */}
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-gray-700">Sort:</span>
                <div className="relative">
                  <select
                    value={sortBy}
                    onChange={(e) => {
                      handleSort(e.target.value);
                      setCurrentPage(1);
                    }}
                    className="appearance-none bg-white border border-gray-300 rounded-xl px-4 py-3 pr-10 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 min-w-[160px]"
                  >
                    {SHIPPING_SORT_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                  <IoChevronDownOutline className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={14} />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Results Info */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <p className="text-sm text-gray-600">
              Showing <span className="font-semibold text-gray-900">{shippings.length}</span> of{" "}
              <span className="font-semibold text-gray-900">{totalItems}</span> shipments
            </p>
            {(searchTerm || statusFilter) && (
              <button
                onClick={() => {
                  setSearchTerm("");
                  setStatusFilter("");
                  setCurrentPage(1);
                }}
                className="text-sm text-green hover:text-green-700 font-medium"
              >
                Clear filters
              </button>
            )}
          </div>
        </div>

      {/* Shipments Display */}
      <div className="space-y-6">
        {loading ? (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12">
            <div className="flex items-center justify-center">
              <LoadingSpinner />
            </div>
          </div>
        ) : error ? (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12">
            <div className="text-center">
              <IoCloseCircleOutline className="w-16 h-16 text-red-400 mx-auto mb-4" />
              <p className="text-red-600 font-medium mb-4">{error}</p>
              <button
                onClick={fetchShippings}
                className="inline-flex items-center gap-2 px-6 py-3 bg-green text-white rounded-lg hover:bg-green-600 transition-colors font-medium"
              >
                <IoCarOutline className="w-4 h-4" />
                Try Again
              </button>
            </div>
          </div>
        ) : shippings.length === 0 ? (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12">
            <div className="text-center">
              <div className="w-24 h-24 bg-gradient-to-br from-gray-100 to-gray-200 rounded-full flex items-center justify-center mx-auto mb-6">
                <IoCarOutline className="w-12 h-12 text-gray-400" />
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-2">No shipments found</h3>
              <p className="text-gray-600 max-w-md mx-auto">
                {searchTerm || statusFilter 
                  ? "Try adjusting your search or filter criteria to find more shipments"
                  : "You haven't won any auctions with shipments yet. Start bidding to see your deliveries here!"
                }
              </p>
              {!searchTerm && !statusFilter && (
                <button className="mt-6 inline-flex items-center gap-2 px-6 py-3 bg-green text-white rounded-lg hover:bg-green-600 transition-colors font-medium">
                  <IoBusinessOutline className="w-4 h-4" />
                  Browse Auctions
                </button>
              )}
            </div>
          </div>
        ) : (
          <>
            {/* Shipments Grid */}
            <div className="grid gap-6">
              {shippings.map((shipping) => {
                const colors = SHIPPING_STATUS_COLORS[shipping.shippingStatus];
                const StatusIcon = getStatusIcon(shipping.shippingStatus);
                
                return (
                  <div 
                    key={`${shipping.id}-${shipping.shippingStatus}-${recentlyConfirmed === shipping.id ? 'confirmed' : ''}`} 
                    className={`bg-white rounded-xl shadow-sm border border-gray-200 hover:shadow-md transition-all duration-200 overflow-hidden ${
                      recentlyConfirmed === shipping.id ? 'ring-2 ring-green-500 shadow-lg' : ''
                    }`}
                  >
                    {/* Status Bar */}
                    <div className={`h-1 ${colors.bg}`}></div>
                    
                    <div className="p-6">
                      <div className="flex flex-col xl:flex-row gap-6">
                        {/* Product Section */}
                        <div className="flex gap-4 flex-1">
                          {/* Product Image */}
                          <div className="flex-shrink-0">
                            {shipping.auction?.product?.images?.[0] ? (
                              <img
                                src={shipping.auction.product.images[0]}
                                alt={shipping.auction.product.name}
                                className="w-24 h-24 object-cover rounded-xl border-2 border-gray-100 shadow-sm"
                              />
                            ) : (
                              <div className="w-24 h-24 bg-gradient-to-br from-gray-50 to-gray-100 rounded-xl border-2 border-gray-100 flex items-center justify-center">
                                <IoImageOutline className="w-8 h-8 text-gray-400" />
                              </div>
                            )}
                          </div>

                          {/* Product Info */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-start justify-between mb-3">
                              <div className="flex-1 min-w-0">
                                <h3 className="text-lg font-semibold text-gray-900 truncate mb-1">
                                  {shipping.auction?.title || 'Auction Title'}
                                </h3>
                                <p className="text-gray-600 text-sm truncate mb-2">
                                  {shipping.auction?.product?.name || 'Product Name'}
                                </p>
                                <div className="flex items-center gap-2 text-sm">
                                  <IoBusinessOutline className="w-4 h-4 text-gray-400" />
                                  <span className="text-gray-600">Seller:</span>
                                  <span className="font-medium text-gray-900">
                                    {shipping.seller?.profile?.fullName || shipping.seller?.email}
                                  </span>
                                </div>
                              </div>
                              <div className="flex flex-col items-end gap-3">
                                <div className={`${colors.bg} ${colors.text} px-4 py-2 rounded-full text-sm font-semibold border ${colors.border} flex items-center gap-2`}>
                                  <StatusIcon className="w-4 h-4" />
                                  {SHIPPING_STATUS_LABELS[shipping.shippingStatus]}
                                </div>
                                
                                {/* Timeline under status */}
                                <div className="space-y-2">
                                  {shipping.shippedAt && (
                                    <div className="flex items-center gap-2">
                                      <div className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center">
                                        <IoCalendarOutline className="w-3 h-3 text-blue-600" />
                                      </div>
                                      <div>
                                        <p className="text-sm font-medium text-gray-900">Shipped</p>
                                        <p className="text-sm text-gray-600">{formatDate(shipping.shippedAt)}</p>
                                      </div>
                                    </div>
                                  )}

                                  {shipping.estimatedDelivery && (
                                    <div className="flex items-center gap-2">
                                      <div className="w-6 h-6 bg-orange-100 rounded-full flex items-center justify-center">
                                        <IoTimeOutline className="w-3 h-3 text-orange-600" />
                                      </div>
                                      <div>
                                        <p className="text-sm font-medium text-gray-900">Est. Delivery</p>
                                        <p className="text-sm text-gray-600">{formatDate(shipping.estimatedDelivery)}</p>
                                      </div>
                                    </div>
                                  )}

                                  {shipping.deliveredAt && (
                                    <div className="flex items-center gap-2">
                                      <div className="w-6 h-6 bg-green-100 rounded-full flex items-center justify-center">
                                        <IoCheckmarkCircleOutline className="w-3 h-3 text-green-600" />
                                      </div>
                                      <div>
                                        <p className="text-xs font-medium text-gray-900">Delivered</p>
                                        <p className="text-xs text-gray-600">{formatDate(shipping.deliveredAt)}</p>
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>

                            {/* Price Info */}
                            {shipping.price && (
                              <div className="inline-flex items-center gap-2 bg-green-50 text-green-700 px-3 py-1 rounded-lg text-sm font-medium">
                                <span>Shipping Cost:</span>
                                <span className="font-bold">{formatVND(shipping.price)}</span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Tracking Section */}
                        <div className="xl:w-80 xl:border-l xl:border-gray-100 xl:pl-6">
                          <div className="space-y-2">
                            {/* Tracking Number */}
                            {shipping.trackingNumber && (
                              <div className="bg-gray-50 rounded-lg p-3">
                                <div className="flex items-center gap-2 mb-1">
                                  <IoCodeWorkingOutline className="w-3 h-3 text-gray-500" />
                                  <span className="text-xs font-medium text-gray-700">Tracking Number</span>
                                </div>
                                <p className="font-mono text-sm font-semibold text-gray-900 bg-white px-2 py-1 rounded border">
                                  {shipping.trackingNumber}
                                </p>
                              </div>
                            )}

                            {/* Actions */}
                            <div className="space-y-2">
                              <button
                                onClick={() => openShippingDetail(shipping)}
                                className="w-full bg-gray-100 text-gray-700 px-4 py-2.5 rounded-lg hover:bg-gray-200 transition-colors flex items-center justify-center gap-2 font-medium text-sm"
                              >
                                <IoEyeOutline className="w-4 h-4" />
                                View Details
                              </button>
                              {shipping.shippingStatus === 'IN_TRANSIT' && (
                                <button
                                  onClick={() => openConfirmDeliveryModal(shipping)}
                                  className="w-full bg-green text-white px-4 py-2.5 rounded-lg hover:bg-green-600 transition-colors flex items-center justify-center gap-2 font-medium text-sm"
                                >
                                  <IoCheckmarkCircleOutline className="w-4 h-4" />
                                  Confirm Delivery
                                </button>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex justify-center pt-2">
                <Pagination
                  currentPage={currentPage}
                  totalPages={totalPages}
                  onPageChange={handlePageChange}
                />
              </div>
            )}
          </>
        )}
      </div>

        {/* Shipping Detail Modal */}
        {isModalOpen && selectedShipping && (
          <ShippingDetailModal
            shipping={selectedShipping}
            isOpen={isModalOpen}
            onClose={closeShippingDetail}
            onConfirmDelivery={openConfirmDeliveryModal}
          />
        )}

        {/* Confirm Delivery Modal */}
        {/* Shipping Detail Modal */}
        {isModalOpen && selectedShipping && (
          <ShippingDetailModal
            shipping={selectedShipping}
            isOpen={isModalOpen}
            onClose={closeShippingDetail}
            onConfirmDelivery={openConfirmDeliveryModal}
          />
        )}

        {/* Confirm Delivery Modal */}
        <ConfirmDeliveryModal
          isOpen={confirmDeliveryModal.isOpen}
          onClose={closeConfirmDeliveryModal}
          onConfirm={handleConfirmDelivery}
          auctionTitle={confirmDeliveryModal.auctionTitle}
          isLoading={confirmDeliveryLoading}
        />
      </div>
    </div>
  );
};

export default ShippingListForBidder;