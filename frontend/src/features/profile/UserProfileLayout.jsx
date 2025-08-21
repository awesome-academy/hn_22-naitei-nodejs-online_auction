import { useState } from "react";
import { UserAccountInfo } from "@/features/profile/UserAccountInfo";
import OrderListForBidder from "@/features/profile/OrderListForBidder";
import ShippingListForBidder from "@/features/profile/ShippingListForBidder";
import { Container } from "@/components/ui/index.js";
import { useUser } from "@/contexts/UserContext.jsx";
import { 
  IoPersonOutline, 
  IoHeartOutline, 
  IoReceiptOutline, 
  IoCardOutline, 
  IoCarOutline 
} from "react-icons/io5";

const ProfileTabs = {
  ACCOUNT: 'Account',
  WATCHLIST: 'Watchlist', 
  ORDER: 'Order',
  PAYMENT_HISTORY: 'Payment history',
  SHIPPING: 'Shipping'
};

const TabIcons = {
  [ProfileTabs.ACCOUNT]: IoPersonOutline,
  [ProfileTabs.WATCHLIST]: IoHeartOutline,
  [ProfileTabs.ORDER]: IoReceiptOutline,
  [ProfileTabs.PAYMENT_HISTORY]: IoCardOutline,
  [ProfileTabs.SHIPPING]: IoCarOutline,
};

export const UserProfileLayout = () => {
  const [activeTab, setActiveTab] = useState(ProfileTabs.ACCOUNT);
  const { user } = useUser();

  const tabComponents = {
    [ProfileTabs.ACCOUNT]: <UserAccountInfo />,
    [ProfileTabs.WATCHLIST]: <div className="text-center py-8">Watchlist - Coming Soon</div>,
    [ProfileTabs.ORDER]: <OrderListForBidder />,
    [ProfileTabs.PAYMENT_HISTORY]: <div className="text-center py-8">Payment History - Coming Soon</div>,
    [ProfileTabs.SHIPPING]: <ShippingListForBidder />,
  };

  // If user is SELLER or ADMIN, only show Account content without sidebar
  if (user?.role === "SELLER" || user?.role === "ADMIN") {
    return (
      <section className="profile pt-8 relative min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
        {/* Background decoration */}
        <div className="bg-blue-400 w-48 h-48 rounded-full opacity-5 blur-3xl absolute bottom-1/4 left-10"></div>
        
        <Container>
          <div className="max-w-4xl mx-auto relative z-10">
            <div className="bg-white rounded-lg shadow-lg border border-gray-200 min-h-[500px]">
              <UserAccountInfo />
            </div>
          </div>
        </Container>
      </section>
    );
  }

  return (
    <section className="profile pt-8 relative min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
      {/* Background decoration */}
      <div className="bg-green w-96 h-96 rounded-full opacity-10 blur-3xl absolute top-2/3 right-0"></div>
      <div className="bg-blue-400 w-64 h-64 rounded-full opacity-5 blur-3xl absolute top-1/4 left-0"></div>
      
      <Container>
        <div className="flex gap-6 relative z-10">
          {/* Left Sidebar with Tabs */}
          <div className="w-48 flex-shrink-0">
            <div className="bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden sticky top-6">
              <div className="p-4 bg-green text-white">
              </div>
              <nav className="py-2">
                {Object.values(ProfileTabs).map((tab) => {
                  const IconComponent = TabIcons[tab];
                  return (
                    <button
                      key={tab}
                      onClick={() => setActiveTab(tab)}
                      className={`w-full text-left px-4 py-3 text-sm font-medium transition-all duration-200 border-l-4 flex items-center gap-3 ${
                        activeTab === tab
                          ? 'bg-green-50 text-green border-green shadow-sm font-semibold'
                          : 'text-gray-600 hover:bg-gray-50 hover:text-green border-transparent'
                      }`}
                    >
                      <IconComponent className="w-5 h-5" />
                      {tab}
                    </button>
                  );
                })}
              </nav>
            </div>
          </div>

          {/* Main Content Area */}
          <div className="flex-1 min-w-0">
            <div className="bg-white rounded-lg shadow-lg border border-gray-200 min-h-[600px]">
              {tabComponents[activeTab]}
            </div>
          </div>
        </div>
      </Container>
    </section>
  );
};
