import {UserProvider} from "@/contexts/UserContext.jsx";
import {BrowserRouter, Route, Routes, Navigate} from "react-router-dom";
import {NotificationProvider} from "@/contexts/NotificationContext.jsx";
import {AuthRoute} from "@/routers/AuthRoutes.jsx";
import Dashboard from "@/screens/Dashboard/index.jsx";

function App() {
  return (
    <BrowserRouter>
      <UserProvider>
          <NotificationProvider>
            <Routes>
              <Route path="/" element={<Navigate to="/auth/login" replace />} />
              <Route path="/auth/*" element={<AuthRoute />}/>
              <Route path="/dashboard" element={<Dashboard />} />
            </Routes>
          </NotificationProvider>
        </UserProvider>
    </BrowserRouter>
  )
}

export default App
