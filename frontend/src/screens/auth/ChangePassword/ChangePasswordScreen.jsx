import { Layout } from "@/components/layout/Layout";
import { ChangePasswordForm } from "@/features/auth/ChangePasswordForm";
import { ChangePasswordHeader } from "@/screens/auth/ChangePassword/ChangePasswordHeader.jsx";

const ChangePasswordScreen = () => {
  return (
    <Layout>
      <ChangePasswordHeader />
      <ChangePasswordForm />
    </Layout>
  );
};

export default ChangePasswordScreen;
