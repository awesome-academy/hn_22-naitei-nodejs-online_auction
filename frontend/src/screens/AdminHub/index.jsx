import React from "react";
import { AdminHubLayout } from "@/components/layout/AdminHubLayout";
import { AdminHubNavigation } from "@/components/layout/AdminHubNavigation";
import { AdminHubUserSidebar } from "@/components/ui/AdminHubUserSidebar";
import { Routes, Route, Navigate } from "react-router-dom";
import BidderManagement from "@/screens/AdminHub/User/BidderManagement/index.jsx";
import SellerManagement from "@/screens/AdminHub/User/SellerManagement/index.jsx";
import OrderManagement from "@/screens/AdminHub/OrderManagement/index.jsx";
import AuctionManagement from "@/screens/AdminHub/AuctionManagement/index.jsx";
import AuctionDetailPage from "@/screens/AdminHub/AuctionManagement/AuctionDetailPage.jsx";
import ComingSoon from "@/screens/AdminHub/ComingSoon/index.jsx";

const AdminHub = () => {
  return (
    <AdminHubLayout>
      <AdminHubNavigation />
      <Routes>
        {/* User Management Routes */}
        <Route path="user/*" element={
          <div className="flex">
            <AdminHubUserSidebar />
            <div className="flex-1 p-6">
              <Routes>
                <Route path="bidder" element={<BidderManagement />} />
                <Route path="seller" element={<SellerManagement />} />
                <Route path="" element={<Navigate to="/admin-hub/user/bidder" replace />} />
              </Routes>
            </div>
          </div>
        } />

        {/* Other Routes - Coming Soon */}
        <Route path="overview" element={<ComingSoon title="Overview" />} />
        <Route path="orders" element={<OrderManagement />} />
        <Route path="auctions" element={<AuctionManagement />} />
        <Route path="auctions/:auctionId" element={<AuctionDetailPage />} />
        <Route path="listings" element={<ComingSoon title="Listings" />} />
        <Route path="store" element={<ComingSoon title="Store" />} />
        <Route path="performance" element={<ComingSoon title="Performance" />} />
        <Route path="payments" element={<ComingSoon title="Payments" />} />
        <Route path="research" element={<ComingSoon title="Research" />} />
        <Route path="reports" element={<ComingSoon title="Reports" />} />

        {/* Default redirect */}
        <Route path="" element={<Navigate to="/admin-hub/user/bidder" replace />} />
        <Route path="*" element={<Navigate to="/admin-hub/user/bidder" replace />} />
      </Routes>
    </AdminHubLayout>
  );
};

export default AdminHub;
