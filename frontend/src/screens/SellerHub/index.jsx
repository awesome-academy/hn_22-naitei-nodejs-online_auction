import React from "react";
import { SellerHubLayout } from "@/components/layout/SellerHubLayout";
import { SellerHubNavigation } from "@/components/layout/SellerHubNavigation";
import { SellerHubListingSidebar } from "@/components/ui/SellerHubListingSidebar";
import { Routes, Route, Navigate } from "react-router-dom";
import ProductListing from "@/screens/SellerHub/Listings/ProductListing/index.jsx";
import AuctionListing from "@/screens/SellerHub/Listings/AuctionListing/index.jsx";
import EditProduct from "@/screens/products/EditProduct/index.jsx";
import CreateAuction from "@/screens/auctions/CreateAuction/index.jsx";

const SellerHub = () => {
  return (
    <SellerHubLayout>
      <SellerHubNavigation />
      <div className="flex">
        <SellerHubListingSidebar />
        <div className="flex-1 p-6">
          <Routes>
            <Route path="listings/product" element={<ProductListing />} />
            <Route path="listings/product/edit/:id" element={<EditProduct />} />
            <Route path="listings/auction" element={<AuctionListing />} />
            <Route path="listings/auction/create" element={<CreateAuction />} />
            <Route path="listings" element={<Navigate to="/seller-hub/listings/product" replace />} />
            <Route path="*" element={<Navigate to="/seller-hub/listings/product" replace />} />
          </Routes>
        </div>
      </div>
    </SellerHubLayout>
  );
};

export default SellerHub;
