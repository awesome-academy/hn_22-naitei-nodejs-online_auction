import { Layout } from "@/components/layout/Layout";
import { useUser } from "@/contexts/UserContext.jsx";
import { Link } from "react-router-dom";

const Dashboard = () => {
  const { user } = useUser();

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8">
        <h1 className="text-3xl font-bold mb-6">Dashboard</h1>
        {user && (
          <div className="bg-white p-6 rounded-lg shadow mb-6">
            <h2 className="text-xl font-semibold mb-4">Welcome, {user.fullName || user.email}!</h2>
            <p className="text-gray-600">Role: {user.role}</p>
          </div>
        )}

        {/* Demo Seller Profile Links */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h2 className="text-xl font-semibold mb-4">Demo: Visit Seller Profiles</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <Link
              to="/seller/123e4567-e89b-12d3-a456-426614174000"
              className="block p-4 border rounded-lg hover:bg-gray-50 transition-colors"
            >
              <h3 className="font-medium text-blue-600">Sample Seller 1</h3>
              <p className="text-sm text-gray-600">Electronics & Gadgets</p>
            </Link>

            <Link
              to="/seller/223e4567-e89b-12d3-a456-426614174000"
              className="block p-4 border rounded-lg hover:bg-gray-50 transition-colors"
            >
              <h3 className="font-medium text-blue-600">Sample Seller 2</h3>
              <p className="text-sm text-gray-600">Fashion & Accessories</p>
            </Link>

            <Link
              to="/seller/323e4567-e89b-12d3-a456-426614174000"
              className="block p-4 border rounded-lg hover:bg-gray-50 transition-colors"
            >
              <h3 className="font-medium text-blue-600">Sample Seller 3</h3>
              <p className="text-sm text-gray-600">Home & Garden</p>
            </Link>
          </div>
          <p className="text-sm text-gray-500 mt-4">
            * These are demo links to test the seller profile functionality. Replace with actual seller IDs when available.
          </p>
        </div>
      </div>
    </Layout>
  );
};

export default Dashboard;
