import React from "react";
import { Title, PrimaryButton } from "@/components/ui/index.js";
import { useNavigate } from "react-router-dom";

const AuctionListing = () => {
  const navigate = useNavigate();

  return (
    <div className="max-w-7xl mx-auto">
      <div className="flex justify-between items-center mb-6">
        <Title level={2} className="text-3xl font-bold text-gray-900">
          Auction Management
        </Title>
        <PrimaryButton
          onClick={() => navigate("/seller-hub/listings/auction/create")}
          className="px-6 py-3 bg-green text-white rounded-lg font-medium hover:bg-green-600 transition-colors"
        >
          Create New Auction
        </PrimaryButton>
      </div>

      <div className="text-center py-12">
        <p className="text-gray-600 text-lg">
          Auction management functionality will be implemented here.
        </p>
        <div className="mt-8 bg-gray-50 border border-gray-200 rounded-lg p-8">
          <h3 className="text-xl font-semibold text-gray-800 mb-4">Coming Soon</h3>
          <p className="text-gray-600">
            This section will allow you to manage your auction listings,
            including creating new auctions, monitoring bids, and managing auction status.
          </p>
        </div>
      </div>
    </div>
  );
};

export default AuctionListing;
