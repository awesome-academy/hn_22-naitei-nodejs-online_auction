import React, { useState } from "react";
import { NavLink } from "react-router-dom";

export const SellerHubListingSidebar = () => {
  const [activeTab, setActiveTab] = useState("product");

  const sidebarItems = [
    {
      id: "auction",
      label: "Auction",
      path: "/seller-hub/listings/auction",
    },
    {
      id: "product",
      label: "Product",
      path: "/seller-hub/listings/product",
    },
  ];

  return (
    <div className="w-48 bg-white border-r border-gray-200 min-h-screen">
      <div className="p-4">
        <nav className="space-y-2">
          {sidebarItems.map((item) => (
            <NavLink
              key={item.id}
              to={item.path}
              onClick={() => setActiveTab(item.id)}
              className={({ isActive }) =>
                `block px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 ${isActive || activeTab === item.id
                  ? "bg-green-50 text-green-700 border-l-4 border-green-500"
                  : "text-gray-600 hover:bg-gray-50 hover:text-gray-900"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </div>
    </div>
  );
};
