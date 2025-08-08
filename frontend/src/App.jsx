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
import ResetPasswordPage from "@/screens/auth/ResetPassword/index.jsx";
// import ChatPage from '@/screens/chat/index.jsx';

function App() {
  return (
    <BrowserRouter>
      <UserProvider>
          <NotificationProvider>
            <Routes>
              <Route path="/" element={<Navigate to="/auth/login" replace />} />
              <Route path="/auth/*" element={<AuthRoute />}/>
              <Route path="/reset" element={<ResetPasswordPage />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/products/*" element={<ProductRoutes />} />
              <Route path="/seller-hub/*" element={<SellerHub />} />
              <Route path="/admin-hub/*" element={<AdminHub />} />
              <Route path="/profile" element={<UserProfileScreen />} />
              <Route path="/chat" element={<ChatPage />} />
            </Routes>
          </NotificationProvider>
        </UserProvider>
    </BrowserRouter>
  )
}

export default App
