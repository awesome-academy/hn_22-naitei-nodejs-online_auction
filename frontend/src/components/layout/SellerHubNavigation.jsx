import React from "react";
import { NavLink } from "react-router-dom";
import { Title } from "../ui/index.js";

export const SellerHubNavigation = () => {
  const navTabs = [
    { id: 1, path: "/seller-hub/overview", label: "Overview" },
    { id: 2, path: "/seller-hub/orders", label: "Orders" },
    { id: 3, path: "/seller-hub/listings", label: "Listings" },
    { id: 4, path: "/seller-hub/marketing", label: "Marketing" },
    { id: 5, path: "/seller-hub/store", label: "Store" },
    { id: 6, path: "/seller-hub/performance", label: "Performance" },
    { id: 7, path: "/seller-hub/payments", label: "Payments" },
    { id: 8, path: "/seller-hub/research", label: "Research" },
    { id: 9, path: "/seller-hub/reports", label: "Reports" },
    { id: 10, path: "/seller-hub/statistics", label: "Statistics" },
  ];

  return (
    <div className="bg-white border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Seller Hub Title */}
        <div className="text-center py-6">
          <Title level={1} className="text-4xl font-bold text-gray-900">
            Seller Hub
          </Title>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex space-x-8 pb-4">
          {navTabs.map((tab) => (
            <NavLink
              key={tab.id}
              to={tab.path}
              className={({ isActive }) =>
                `text-sm font-medium transition-colors duration-200 pb-2 border-b-2 ${isActive
                  ? "text-gray-900 border-gray-900"
                  : "text-gray-500 border-transparent hover:text-gray-700 hover:border-gray-300"
                }`
              }
            >
              {tab.label}
            </NavLink>
          ))}
        </nav>
      </div>
    </div>
  );
};
