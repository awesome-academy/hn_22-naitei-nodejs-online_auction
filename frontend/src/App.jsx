import { UserProvider } from "@/contexts/UserContext.jsx";
import { BrowserRouter, Route, Routes, Navigate } from "react-router-dom";
import { NotificationProvider } from "@/contexts/NotificationContext.jsx";
import { AuthRoute } from "@/routers/AuthRoutes.jsx";
import { ProductRoutes } from "@/routers/ProductRoutes.jsx";
import { AuctionRoutes } from "@/routers/AuctionRoutes.jsx";
import Dashboard from "@/screens/Dashboard/index.jsx";
import SellerHub from "@/screens/SellerHub/index.jsx";
import AdminHub from "@/screens/AdminHub/index.jsx";
import UserProfileScreen from "@/screens/profile/UserProfileScreen.jsx";
import SellerProfile from "@/screens/profile/SellerProfile.jsx";
import ResetPasswordPage from "@/screens/auth/ResetPassword/index.jsx";
import ChatPage from '@/screens/chat/index.jsx';
import AddFunds from '@/screens/wallet/AddFunds-QR';
import WalletDashboard from '@/screens/wallet/WalletDashboard';
import { WalletProvider } from './contexts/WalletContext';
import { Toaster } from 'react-hot-toast';

function App() {
  return (
    <BrowserRouter>
      <UserProvider>
        <NotificationProvider>
          <WalletProvider>
            <Toaster position="top-right" />
            <Routes>
              <Route path="/" element={<Navigate to="/auth/login" replace />} />
              <Route path="/auth/*" element={<AuthRoute />} />
              <Route path="/reset" element={<ResetPasswordPage />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/auctions/*" element={<AuctionRoutes />} />
              <Route path="/products/*" element={<ProductRoutes />} />
              <Route path="/seller-hub/*" element={<SellerHub />} />
              <Route path="/admin-hub/*" element={<AdminHub />} />
              <Route path="/profile" element={<UserProfileScreen />} />
              <Route path="/seller/:sellerId" element={<SellerProfile />} />
              <Route path="/chat" element={<ChatPage />} />
              <Route path="/wallet" element={<WalletDashboard />} />
              <Route path="/wallet/add-funds" element={<AddFunds />} />
            </Routes>
          </WalletProvider>
        </NotificationProvider>
      </UserProvider>
    </BrowserRouter>
  );
}

export default App;
