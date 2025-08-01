import { useState } from "react";
import { useNotification } from "@/contexts/NotificationContext.jsx";
import { useNavigate } from "react-router-dom";
import { useUser } from "@/contexts/UserContext.jsx";
import { registerUser } from "@/services/authService.js";

export const useRegister = () => {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isSeller, setIsSeller] = useState(false);
  const [agreeToTerms, setAgreeToTerms] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  
  const { showToastNotification } = useNotification();
  const navigate = useNavigate();
  const { login } = useUser();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    // Validation
    if (!fullName.trim()) {
      setError("Full name is required");
      setLoading(false);
      return;
    }

    if (!email.trim()) {
      setError("Email is required");
      setLoading(false);
      return;
    }

    if (!password.trim()) {
      setError("Password is required");
      setLoading(false);
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match");
      setLoading(false);
      return;
    }

    if (!agreeToTerms) {
      setError("You must agree to the Terms & Policy");
      setLoading(false);
      return;
    }

    try {
      const response = await registerUser({
        email: email.trim(),
        password: password.trim(),
        isSeller: isSeller
      });

      if (response?.user) {
        login({
          id: response.user.id,
          email: response.user.email,
          role: response.user.role,
          accessToken: response.user.accessToken,
          refreshToken: response.user.refreshToken,
        });
        showToastNotification('Registration successful!', 'success');
        navigate('/');
      }
    } catch (err) {
      console.error('Registration error:', err);
      setError(err.message || 'Registration failed');
      showToastNotification(err.message || 'Registration failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  return {
    fullName,
    setFullName,
    email,
    setEmail,
    password,
    setPassword,
    confirmPassword,
    setConfirmPassword,
    isSeller,
    setIsSeller,
    agreeToTerms,
    setAgreeToTerms,
    handleSubmit,
    error,
    loading,
  };
};
