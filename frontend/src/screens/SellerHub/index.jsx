import React from "react";
import { SellerHubLayout } from "@/components/layout/SellerHubLayout";
import { SellerHubNavigation } from "@/components/layout/SellerHubNavigation";
import { SellerHubListingSidebar } from "@/components/ui/SellerHubListingSidebar";
import { Routes, Route, Navigate } from "react-router-dom";
import ProductListing from "@/screens/SellerHub/Listings/ProductListing/index.jsx";
import AuctionListing from "@/screens/SellerHub/Listings/AuctionListing/index.jsx";
import SellerStatistics from "@/screens/SellerHub/Statistics/index.jsx";
import EditProduct from "@/screens/products/EditProduct/index.jsx";
import CreateAuction from "@/screens/auctions/CreateAuction/index.jsx";
import SellerOrderManagement from "@/screens/SellerHub/OrderManagement/index.jsx";

const SellerHub = () => {
  return (
    <SellerHubLayout>
      <SellerHubNavigation />
      
      <Routes>
        {/* Orders Management */}
        <Route path="orders" element={<SellerOrderManagement />} />
        
        {/* Listings Management */}
        <Route path="statistics" element={<div className="p-6"><SellerStatistics /></div>} />
        <Route path="listings/*" element={
          <div className="flex">
            <SellerHubListingSidebar />
            <div className="flex-1 p-6">
              <Routes>
                <Route path="product" element={<ProductListing />} />
                <Route path="product/edit/:id" element={<EditProduct />} />
                <Route path="auction" element={<AuctionListing />} />
                <Route path="auction/create" element={<CreateAuction />} />
                <Route path="" element={<Navigate to="/seller-hub/listings/product" replace />} />
              </Routes>
            </div>
          </div>
        } />
        
        {/* Default redirects */}
        <Route path="" element={<Navigate to="/seller-hub/orders" replace />} />
        <Route path="*" element={<Navigate to="/seller-hub/orders" replace />} />
        <Route path="" element={<Navigate to="/seller-hub/listings/product" replace />} />
        <Route path="*" element={<Navigate to="/seller-hub/listings/product" replace />} />
      </Routes>
    </SellerHubLayout>
  );
};

export default SellerHub;
