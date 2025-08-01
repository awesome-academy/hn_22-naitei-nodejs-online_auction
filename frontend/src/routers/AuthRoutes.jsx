import { Route, Routes } from "react-router-dom";
import Register from "@/screens/auth/Register/index.jsx";
import LoginScreen from "@/screens/auth/LoginScreen.jsx";

export const AuthRoute = () => {
  return (
    <Routes>
      <Route path="login" element={< LoginScreen/>} />
      <Route path="register" element={< Register/>} />
    </Routes>
  );
};
