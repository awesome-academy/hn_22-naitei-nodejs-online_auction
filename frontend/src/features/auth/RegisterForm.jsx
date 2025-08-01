import {
  Caption,
  Container,
  CustomNavLink,
  PrimaryButton,
  Title,
  commonClassNameOfInput,
} from "@/components/ui/index.js";
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useNotification } from "@/contexts/NotificationContext.jsx";
import { useUser } from "@/contexts/UserContext.jsx";
import { useRegister } from "@/hooks/useRegister.js";

export const RegisterForm = () => {
  const { user, loading: userLoading } = useUser();
  const { showToastNotification } = useNotification();
  const navigate = useNavigate();
  const {
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
  } = useRegister();

  useEffect(() => {
    if (!userLoading && user.id && user.email && user.role) {
      showToastNotification(`You are already logged in as ${user.email}`, "info");
      navigate("/dashboard"); // Redirect to dashboard instead of "/"
    }
  }, [userLoading, navigate, showToastNotification, user]);

  return (
    <section className="register pt-16 relative">
      <div className="bg-green w-96 h-96 rounded-full opacity-20 blur-3xl absolute top-2/3"></div>

      <div className="bg-[#241C37] pt-8 h-[40vh] relative content">
        <Container>
          <div>
            <Title level={3} className="text-white">
              Sign Up
            </Title>
            <div className="flex items-center gap-3">
              <Title level={5} className="text-green font-normal text-xl">Home</Title>
              <Title level={5} className="text-white font-normal text-xl">/</Title>
              <Title level={5} className="text-white font-normal text-xl">Sign Up</Title>
            </div>
          </div>
        </Container>
      </div>

      <div className="transition-all duration-500 ease-in-out transform translate-x-0">
        <div className="bg-white shadow-s3 w-1/3 m-auto my-16 p-8 rounded-xl">
          <form onSubmit={handleSubmit}>
            <div className="text-center">
              <Title level={5}>Sign Up</Title>
              <p className="mt-2 text-lg">
                Do you already have an account?{" "}
                <CustomNavLink href="/auth/login">Log In Here</CustomNavLink>
              </p>
            </div>

            {error && (
              <div className="text-center">
                <div className="text-red-500 mt-4">{error}</div>
              </div>
            )}

            <div className="py-5 mt-8">
              <Caption className="mb-2">Fullname *</Caption>
              <input
                type="text"
                name="fullName"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                className={commonClassNameOfInput}
                placeholder="Full Name"
                required
              />
            </div>

            <div className="pb-5">
              <Caption className="mb-2">Enter Your Email *</Caption>
              <input
                type="email"
                name="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className={commonClassNameOfInput}
                placeholder="Enter Your Email"
                required
              />
            </div>

            <div className="pb-5">
              <Caption className="mb-2">Password *</Caption>
              <input
                type="password"
                name="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={commonClassNameOfInput}
                placeholder="Enter Your Password"
                required
              />
            </div>

            <div className="pb-5">
              <Caption className="mb-2">Confirm Password *</Caption>
              <input
                type="password"
                name="confirmPassword"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className={commonClassNameOfInput}
                placeholder="Confirm password"
                required
              />
            </div>

            <div className="pb-5">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={isSeller}
                  onChange={(e) => setIsSeller(e.target.checked)}
                  className="w-4 h-4 text-green bg-gray-100 border-gray-300 rounded focus:ring-green focus:ring-2"
                />
                <span className="text-sm text-gray-700">Become a Seller</span>
              </label>
            </div>

            <div className="pb-5">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={agreeToTerms}
                  onChange={(e) => setAgreeToTerms(e.target.checked)}
                  className="w-4 h-4 text-green bg-gray-100 border-gray-300 rounded focus:ring-green focus:ring-2"
                  required
                />
                <span className="text-sm text-gray-700">
                  I agree to the{" "}
                  <CustomNavLink href="/terms" className="text-green font-medium">
                    Terms & Policy
                  </CustomNavLink>
                </span>
              </label>
            </div>

            <PrimaryButton 
              className="w-full rounded-none my-5" 
              disabled={loading}
            >
              {loading ? "CREATING ACCOUNT..." : "CREATE ACCOUNT"}
            </PrimaryButton>

            <div className="text-center mt-6">
              <p className="text-gray-600 mb-4">OR SIGNUP WITH</p>
              <div className="flex gap-4 justify-center">
                <button
                  type="button"
                  className="flex items-center gap-2 px-4 py-2 bg-red-500 text-white rounded-md hover:bg-red-600 transition-colors"
                >
                  <svg className="w-5 h-5" viewBox="0 0 24 24">
                    <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                  </svg>
                  SIGNUP WITH GOOGLE
                </button>
                <button
                  type="button"
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
                >
                  <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/>
                  </svg>
                  SIGNUP WITH FACEBOOK
                </button>
              </div>
            </div>

            <div className="text-center mt-6 text-sm text-gray-600">
              <p>
                By clicking the signup button, you create a Cobiro account, and you agree to Cobiro's{" "}
                <CustomNavLink href="/terms" className="text-green">
                  Terms & Conditions
                </CustomNavLink>
                {" & "}
                <CustomNavLink href="/privacy" className="text-green">
                  Privacy Policy
                </CustomNavLink>
              </p>
            </div>
          </form>
        </div>
      </div>
    </section>
  );
};
