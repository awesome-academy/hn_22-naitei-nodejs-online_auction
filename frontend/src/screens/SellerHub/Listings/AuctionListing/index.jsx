import React, { useState } from "react";
import { Title, PrimaryButton, SecondaryButton, LoadingSpinner, CancelAuctionModal } from "@/components/ui/index.js";
import { useNavigate } from "react-router-dom";
import { useAuctionListing } from "@/hooks/useAuctionListing.js";
import { AUCTION_STATUS, getAuctionStatusConfig } from "@/constants/auctionStatus.js";
import { IoCreateOutline, IoBanOutline, IoSearchOutline, IoChevronDownOutline } from "react-icons/io5";

const AuctionListing = () => {
  const navigate = useNavigate();
  const {
    auctions,
    loading,
    cancelLoading,
    searchTerm,
    setSearchTerm,
    filterPeriod,
    setFilterPeriod,
    sortBy,
    setSortBy,
    formatDate,
    formatPrice,
    handleEditAuction,
    handleCancelAuction,
    handleReopenAuction,
  } = useAuctionListing();

  // Modal state
  const [cancelModalOpen, setCancelModalOpen] = useState(false);
  const [selectedAuction, setSelectedAuction] = useState(null);

  const openCancelModal = (auction) => {
    setSelectedAuction(auction);
    setCancelModalOpen(true);
  };

  const closeCancelModal = () => {
    setCancelModalOpen(false);
    setSelectedAuction(null);
  };

  const handleConfirmCancel = async (auctionId, reason) => {
    try {
      await handleCancelAuction(auctionId, reason);
      closeCancelModal();
    } catch (error) {
      // Error is already handled in the hook
    }
  };

  const getStatusBadge = (status) => {
    const config = getAuctionStatusConfig(status);

    return (
      <span
        className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium ${config.bg} ${config.text}`}
        title={config.tooltip}
      >
        <config.icon size={14} />
        {config.label}
      </span>
    );
  };

  const getActionButtons = (auction) => {
    switch (auction.status) {
      case AUCTION_STATUS.PENDING:
        return (
          <div className="flex gap-2">
            <button
              onClick={() => handleEditAuction(auction)}
              className="p-2 rounded-md text-blue-600 bg-blue-50 hover:bg-blue-100 hover:text-blue-700 transition-colors"
              title="Edit Auction"
            >
              <IoCreateOutline size={16} />
            </button>
            <button
              onClick={() => openCancelModal(auction)}
              className="p-2 rounded-md text-red-600 bg-red-50 hover:bg-red-100 hover:text-red-700 transition-colors"
              title="Cancel Auction"
            >
              <IoBanOutline size={16} />
            </button>
          </div>
        );
      case AUCTION_STATUS.CANCELED:
        return (
          <div className="flex gap-2">
            <SecondaryButton
              onClick={() => handleReopenAuction(auction)}
              className="px-3 py-1 text-sm bg-green-50 border border-green-200 text-green-700 rounded-md hover:bg-green-100 transition-colors"
            >
              Reopen
            </SecondaryButton>
          </div>
        );
      case AUCTION_STATUS.OPEN:
      case AUCTION_STATUS.READY:
        return (
          <div className="flex gap-2">
            <span className="text-gray-400 text-sm">In progress</span>
          </div>
        );
      case AUCTION_STATUS.COMPLETED:
        return (
          <div className="flex gap-2">
            <span className="text-green-600 text-sm font-medium">Completed</span>
          </div>
        );
      case AUCTION_STATUS.COMPLETED:
        return (
          <div className="flex gap-2">
            <span className="text-green-600 text-sm font-medium">Completed</span>
          </div>
        );
      default:
        return (
          <div className="flex gap-2">
            <span className="text-gray-400 text-sm">No actions</span>
          </div>
        );
    }
  };

  if (loading) {
    return <LoadingSpinner text="Loading auctions..." />;
  }

  return (
    <div className="max-w-7xl mx-auto">
      {/* Header Section */}
      <div className="flex justify-between items-center mb-8">
        <Title level={2} className="text-3xl font-bold text-gray-900">
          Manage auction
        </Title>
        <div className="relative">
          <PrimaryButton
            onClick={() => navigate("/seller-hub/listings/auction/create")}
            className="px-6 py-2 bg-[#365e32] text-white rounded-full font-medium hover:bg-green-700 transition-colors flex items-center gap-2"
          >
            Create auction
            <IoChevronDownOutline size={16} />
          </PrimaryButton>
        </div>
      </div>

      {/* Filters Section */}
      <div className="bg-white border border-gray-300 rounded-lg p-6 mb-6">
        <div className="flex flex-wrap gap-4 items-center">
          {/* Period Filter */}
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-700">Period:</span>
            <div className="relative">
              <select
                value={filterPeriod}
                onChange={(e) => setFilterPeriod(e.target.value)}
                className="appearance-none bg-white border border-gray-300 rounded-lg px-4 py-2 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-green-500"
              >
                <option>Last 90 days</option>
                <option>Last 30 days</option>
                <option>Last 7 days</option>
                <option>All time</option>
              </select>
              <IoChevronDownOutline className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400" size={16} />
            </div>
          </div>

          {/* Search Filter */}
          <div className="flex items-center gap-2 flex-1 max-w-md">
            <span className="text-sm text-gray-700">Search by:</span>
            <div className="relative flex-1">
              <select className="appearance-none bg-white border border-gray-300 rounded-lg px-4 py-2 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-green-500">
                <option>Auction title</option>
                <option>Product name</option>
                <option>Status</option>
              </select>
              <IoChevronDownOutline className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400" size={16} />
            </div>
            <div className="relative flex-1">
              <input
                type="text"
                placeholder="Search..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-green-500"
              />
            </div>
          </div>

          {/* Search Button */}
          <button className="bg-[#365e32] text-white p-2 rounded-lg hover:bg-green-700 transition-colors">
            <IoSearchOutline size={20} />
          </button>
        </div>

        {/* Sort By */}
        <div className="flex justify-end mt-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-700">Sorted by:</span>
            <div className="relative">
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="appearance-none bg-white border border-gray-300 rounded-lg px-4 py-2 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-green-500"
              >
                <option>Current price</option>
                <option>Start date</option>
                <option>End date</option>
                <option>Status</option>
              </select>
              <IoChevronDownOutline className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400" size={16} />
            </div>
          </div>
        </div>
      </div>

      {/* Table Section */}
      <div className="bg-white border border-gray-300 rounded-lg overflow-hidden">
        {/* Table Header */}
        <div className="grid grid-cols-7 gap-4 p-4 bg-gray-50 border-b border-gray-200 text-sm font-medium text-gray-700">
          <div>Auction</div>
          <div>Start</div>
          <div>End</div>
          <div>Start Price</div>
          <div>Current Price</div>
          <div>Status</div>
          <div>Actions</div>
        </div>

        {/* Table Body */}
        <div className="divide-y divide-gray-200">
          {auctions.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-gray-500 text-lg mb-4">No auctions found</p>
              <PrimaryButton
                onClick={() => navigate("/seller-hub/listings/auction/create")}
                className="px-6 py-3 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors"
              >
                Create your first auction
              </PrimaryButton>
            </div>
          ) : (
            auctions.map((auction) => (
              <div key={auction.auctionId} className="grid grid-cols-7 gap-4 p-4 items-center hover:bg-gray-50 transition-colors duration-200">
                {/* Auction Info */}
                <div className="flex items-center gap-3">
                  <div className="w-16 h-16 bg-gray-200 rounded-lg flex items-center justify-center">
                    <div className="w-full h-full bg-gray-300 rounded-lg flex items-center justify-center text-gray-500 text-xs">
                      IMG
                    </div>
                  </div>
                  <div>
                    <h3 className="font-medium text-gray-900 text-sm leading-tight">
                      {auction.title}
                    </h3>
                  </div>
                </div>

                {/* Start Date */}
                <div className="text-sm text-gray-700">
                  {formatDate(auction.startTime)}
                </div>

                {/* End Date */}
                <div className="text-sm text-gray-700">
                  {formatDate(auction.endTime)}
                </div>

                {/* Start Price */}
                <div className="text-sm text-gray-900 font-medium">
                  {formatPrice(auction.startingPrice)}
                </div>

                {/* Current Price */}
                <div className="text-sm text-gray-900 font-medium">
                  {formatPrice(auction.currentPrice)}
                </div>

                {/* Status */}
                <div>
                  {getStatusBadge(auction.status)}
                </div>

                {/* Actions */}
                <div>
                  {getActionButtons(auction)}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Cancel Auction Modal */}
      <CancelAuctionModal
        isOpen={cancelModalOpen}
        onClose={closeCancelModal}
        onConfirm={handleConfirmCancel}
        auction={selectedAuction}
        loading={cancelLoading}
      />
    </div>
  );
};

export default AuctionListing;
