import { Layout } from "@/components/layout/Layout";
import { useUser } from "@/contexts/UserContext.jsx";

const Dashboard = () => {
  const { user } = useUser();

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8">
        <h1 className="text-3xl font-bold mb-6">Dashboard</h1>
        {user && (
          <div className="bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-semibold mb-4">Welcome, {user.fullName || user.email}!</h2>
            <p className="text-gray-600">Role: {user.role}</p>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default Dashboard;
