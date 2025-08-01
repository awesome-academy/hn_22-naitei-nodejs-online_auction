import { Container, Title, PrimaryButton, Caption } from "@/components/ui/index.js";
import { commonClassNameOfInput } from "@/components/ui/Design";
import { authService } from "@/services/auth.service.js";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useNotification } from "@/contexts/NotificationContext.jsx";
import { useUser } from "@/contexts/UserContext.jsx";

export const ChangePasswordForm = () => {
  const [email, setEmail] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [errorMessage, setErrorMessage] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);
  const [loading, setLoading] = useState(false);

  const { user } = useUser();
  const navigate = useNavigate();
  const { showToastNotification } = useNotification();

  // Auto-fill email from user context
  const emailValue = email || user?.email || "";
  const isEmailFromContext = !!user?.email;

  const handleCurrentPasswordChange = (e) => {
    setCurrentPassword(e.target.value);
    setErrorMessage(null);
  };

  const handleNewPasswordChange = (e) => {
    setNewPassword(e.target.value);
    setErrorMessage(null);
  };

  const handleConfirmPasswordChange = (e) => {
    setConfirmPassword(e.target.value);
    setErrorMessage(null);
  };

  const handleEmailChange = (e) => {
    setEmail(e.target.value);
    setErrorMessage(null);
    setSuccessMessage(null);
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setLoading(true);
    setSuccessMessage(null);
    setErrorMessage(null);


    if (newPassword !== confirmPassword) {
      setErrorMessage("New passwords do not match.");
      setLoading(false);
      return;
    }

    if (newPassword.length < 6) {
      setErrorMessage("New password must be at least 6 characters long.");
      setLoading(false);
      return;
    }

    try {
      await authService.changePassword({
        currentPassword: currentPassword.trim(),
        newPassword: newPassword.trim(),
      });

      showToastNotification("Password has been changed successfully.", "success");

      // Clear form
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      if (!isEmailFromContext) setEmail("");

      // Navigate to dashboard or account
      navigate("/dashboard");

    } catch (error) {
      console.error("Change password error:", error);

      const message = error?.response?.data?.message || error.message || "Failed to change password. Please try again.";
      setErrorMessage(message);
      showToastNotification(message, "error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container>
      <form
        className="bg-white shadow-s3 w-1/3 m-auto my-16 p-8 rounded-xl"
        onSubmit={handleChangePassword}
      >
        <div className="text-center">
          <Title level={5}>Change Password</Title>
          <p className="mt-2 text-gray-600">
            Update your account password for security
          </p>
        </div>

        {errorMessage && (
          <div className="text-red-500 mt-4 text-center p-3 bg-red-50 rounded-md border border-red-200">
            {errorMessage}
          </div>
        )}

        {successMessage && (
          <div className="text-green mt-4 text-center p-3 bg-green-50 rounded-md border border-green-200">
            {successMessage}
          </div>
        )}

        {/* Email field - hidden if user is logged in */}
        {!isEmailFromContext && (
          <div className="py-5">
            <Caption className="mb-2">Email *</Caption>
            <input
              type="email"
              name="email"
              value={emailValue}
              onChange={handleEmailChange}
              className={commonClassNameOfInput}
              placeholder="Enter your email"
              required
              disabled={loading}
            />
          </div>
        )}

        <div className="py-5">
          <Caption className="mb-2">Current Password *</Caption>
          <input
            type="password"
            value={currentPassword}
            onChange={handleCurrentPasswordChange}
            className={commonClassNameOfInput}
            placeholder="Enter current password"
            required
            disabled={loading}
          />
        </div>

        <div className="py-5">
          <Caption className="mb-2">New Password *</Caption>
          <input
            type="password"
            value={newPassword}
            onChange={handleNewPasswordChange}
            className={commonClassNameOfInput}
            placeholder="Enter new password (min 6 characters)"
            required
            minLength={6}
            disabled={loading}
          />
        </div>

        <div className="py-5">
          <Caption className="mb-2">Confirm New Password *</Caption>
          <input
            type="password"
            value={confirmPassword}
            onChange={handleConfirmPasswordChange}
            className={commonClassNameOfInput}
            placeholder="Confirm new password"
            required
            disabled={loading}
          />
        </div>

        <div className="flex gap-4">
          <PrimaryButton
            className="flex-1 rounded-none my-5"
            type="submit"
            disabled={loading}
          >
            {loading ? "CHANGING..." : "CHANGE PASSWORD"}
          </PrimaryButton>

          <button
            type="button"
            onClick={() => navigate(-1)}
            className="flex-1 px-6 py-3 my-5 bg-gray-500 text-white font-medium rounded-none hover:bg-gray-600 transition-colors disabled:opacity-50"
            disabled={loading}
          >
            CANCEL
          </button>
        </div>

        {/* Password requirements */}
        <div className="mt-4 p-4 bg-blue-50 rounded-md">
          <h4 className="font-medium text-blue-800 mb-2">Password Requirements:</h4>
          <ul className="text-sm text-blue-700 space-y-1">
            <li>• At least 6 characters long</li>
            <li>• Both new password fields must match</li>
          </ul>
        </div>
      </form>
    </Container>
  );
};
