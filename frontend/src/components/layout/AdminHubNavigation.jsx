import React from "react";
import { NavLink } from "react-router-dom";
import { Title } from "../ui/index.js";

export const AdminHubNavigation = () => {
  const navTabs = [
    { id: 1, path: "/admin-hub/overview", label: "Overview" },
    { id: 2, path: "/admin-hub/orders", label: "Orders" },
    { id: 3, path: "/admin-hub/auctions", label: "Auctions" },
    { id: 4, path: "/admin-hub/listings", label: "Listings" },
    { id: 5, path: "/admin-hub/user", label: "User" },
    { id: 6, path: "/admin-hub/store", label: "Store" },
    { id: 7, path: "/admin-hub/performance", label: "Performance" },
    { id: 8, path: "/admin-hub/payments", label: "Payments" },
    { id: 9, path: "/admin-hub/research", label: "Research" },
    { id: 10, path: "/admin-hub/reports", label: "Reports" },
  ];

  return (
    <div className="bg-white border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Admin Hub Title */}
        <div className="text-center py-6">
          <Title level={1} className="text-4xl font-bold text-gray-900">
            Admin Hub
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
