import React, { useState, useEffect, useCallback } from "react";
import { Title } from "@/components/ui/index.js";
import { userManagementService } from "@/services/userManagement.service";
import { useNotification } from "@/contexts/NotificationContext";
import UserManagementTable from "../components/UserManagementTable";
import UserManagementFilters from "../components/UserManagementFilters";
import WarningModal from "../components/WarningModal";
import ConfirmBanModal from "../components/ConfirmBanModal";
import ViewWarningsModal from "../components/ViewWarningsModal";
import Pagination from "@/components/ui/Pagination";

const SellerManagement = () => {
  const [users, setUsers] = useState([]);
  const [filteredUsers, setFilteredUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Modal states
  const [warningModal, setWarningModal] = useState({ isOpen: false, user: null });
  const [banModal, setBanModal] = useState({ isOpen: false, user: null });
  const [viewWarningsModal, setViewWarningsModal] = useState({ isOpen: false, user: null, warnings: null });

  // Loading states
  const [isBanLoading, setIsBanLoading] = useState(false);
  const [isViewWarningsLoading, setIsViewWarningsLoading] = useState(false);

  // Filter states
  const [searchTerm, setSearchTerm] = useState("");
  const [period, setPeriod] = useState("all");
  const [searchBy, setSearchBy] = useState("all");
  const [sortBy, setSortBy] = useState("createdAt");
  const [sortOrder, setSortOrder] = useState("desc");
  const [statusFilter, setStatusFilter] = useState("all");

  // Pagination state
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 10,
    total: 0,
    totalPages: 0,
    hasNext: false,
    hasPrevious: false
  });

  const { showToastNotification } = useNotification();

  const fetchSellers = useCallback(async (page = 1, limit = 10) => {
    try {
      setLoading(true);
      setError("");
      const response = await userManagementService.getUsersByRole("SELLER", page, limit);

      setUsers(response.users || []);
      setPagination(response.pagination || {
        page: 1,
        limit: 10,
        total: 0,
        totalPages: 0,
        hasNext: false,
        hasPrevious: false
      });
    } catch (err) {
      setError(err.message || "Failed to fetch sellers");
      showToastNotification("Failed to fetch sellers", "error");
    } finally {
      setLoading(false);
    }
  }, [showToastNotification]);

  const filterAndSortUsers = useCallback(() => {
    let filtered = [...users];

    // Apply search filter
    if (searchTerm) {
      filtered = filtered.filter(user => {
        const searchLower = searchTerm.toLowerCase();
        switch (searchBy) {
          case "email":
            return user.email?.toLowerCase().includes(searchLower);
          case "fullName":
            return user.profile?.fullName?.toLowerCase().includes(searchLower) ||
                   user.fullName?.toLowerCase().includes(searchLower);
          case "phoneNumber":
            return user.profile?.phoneNumber?.includes(searchTerm) ||
                   user.phone?.includes(searchTerm);
          case "userId":
            return user.userId?.toString().includes(searchTerm);
          case "all":
            return (
              user.email?.toLowerCase().includes(searchLower) ||
              user.profile?.fullName?.toLowerCase().includes(searchLower) ||
              user.fullName?.toLowerCase().includes(searchLower) ||
              user.profile?.phoneNumber?.includes(searchTerm) ||
              user.phone?.includes(searchTerm) ||
              user.userId?.toString().includes(searchTerm)
            );
          default:
            return true;
        }
      });
    }

    // Apply status filter
    if (statusFilter !== "all") {
      const now = new Date();
      const sevenDaysAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);

      filtered = filtered.filter(user => {
        switch (statusFilter) {
          case "active":
            return !user.isBanned;
          case "banned":
            return user.isBanned;
          case "new":
            return new Date(user.createdAt) >= sevenDaysAgo;
          default:
            return true;
        }
      });
    }

    // Apply period filter
    if (period !== "all") {
      const now = new Date();
      let cutoffDate;

      switch (period) {
        case "today":
          cutoffDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
          break;
        case "7days":
          cutoffDate = new Date(now - 7 * 24 * 60 * 60 * 1000);
          break;
        case "30days":
          cutoffDate = new Date(now - 30 * 24 * 60 * 60 * 1000);
          break;
        case "90days":
          cutoffDate = new Date(now - 90 * 24 * 60 * 60 * 1000);
          break;
        case "6months":
          cutoffDate = new Date(now - 180 * 24 * 60 * 60 * 1000);
          break;
        case "1year":
          cutoffDate = new Date(now - 365 * 24 * 60 * 60 * 1000);
          break;
        default:
          cutoffDate = null;
      }

      if (cutoffDate) {
        filtered = filtered.filter(user => new Date(user.createdAt) >= cutoffDate);
      }
    }

    // Apply sorting
    filtered.sort((a, b) => {
      let valueA, valueB;

      switch (sortBy) {
        case "createdAt":
          valueA = new Date(a.createdAt);
          valueB = new Date(b.createdAt);
          break;
        case "email":
          valueA = a.email || "";
          valueB = b.email || "";
          break;
        case "fullName":
          valueA = a.profile?.fullName || a.fullName || "";
          valueB = b.profile?.fullName || b.fullName || "";
          break;
        case "phoneNumber":
          valueA = a.profile?.phoneNumber || a.phone || "";
          valueB = b.profile?.phoneNumber || b.phone || "";
          break;
        case "lastActivity":
          valueA = new Date(a.lastLoginAt || a.createdAt);
          valueB = new Date(b.lastLoginAt || b.createdAt);
          break;
        default:
          valueA = a.createdAt;
          valueB = b.createdAt;
      }

      if (valueA < valueB) return sortOrder === "asc" ? -1 : 1;
      if (valueA > valueB) return sortOrder === "asc" ? 1 : -1;
      return 0;
    });

    setFilteredUsers(filtered);
  }, [users, searchTerm, searchBy, statusFilter, period, sortBy, sortOrder]);

  useEffect(() => {
    fetchSellers(1, 10);
  }, [fetchSellers]);

  useEffect(() => {
    filterAndSortUsers();
  }, [filterAndSortUsers]);

  // Handle pagination change
  const handlePageChange = (newPage) => {
    fetchSellers(newPage, pagination.limit);
  };

  const handleCreateWarning = (user) => {
    setWarningModal({ isOpen: true, user });
  };

  const handleBanUser = (user) => {
    setBanModal({ isOpen: true, user });
  };

  const handleUnbanUser = async (user) => {
    if (!window.confirm(`Are you sure you want to unban ${user.profile?.fullName || user.email}?`)) {
      return;
    }

    try {
      const result = await userManagementService.unbanUser(user.userId);

      // Update user in state
      setUsers(prevUsers =>
        prevUsers.map(u =>
          u.userId === user.userId
            ? { ...u, isBanned: false }
            : u
        )
      );

      showToastNotification(
        result.message || `${user.profile?.fullName || user.email} has been unbanned`,
        'success'
      );
    } catch (error) {
      showToastNotification(error.message || 'Failed to unban user', 'error');
    }
  };

  const handleViewWarnings = async (user) => {
    setViewWarningsModal({ isOpen: true, user, warnings: null });
    setIsViewWarningsLoading(true);

    try {
      const warnings = await userManagementService.getUserWarnings(user.userId);
      setViewWarningsModal(prev => ({ ...prev, warnings }));
    } catch (error) {
      showToastNotification(error.message || 'Failed to load warnings', 'error');
      setViewWarningsModal(prev => ({ ...prev, warnings: null }));
    } finally {
      setIsViewWarningsLoading(false);
    }
  };

  const handleRemoveWarning = async (warningId) => {
    try {
      const result = await userManagementService.removeWarning(warningId);

      // Update warnings in modal
      setViewWarningsModal(prev => ({
        ...prev,
        warnings: {
          ...prev.warnings,
          warnings: prev.warnings.warnings.filter(w => w.warningId !== warningId),
          warningCount: result.warningCount
        }
      }));

      // Update user in state
      setUsers(prevUsers =>
        prevUsers.map(u =>
          u.userId === viewWarningsModal.user.userId
            ? {
              ...u,
              warningCount: result.warningCount,
              isBanned: result.isBanned
            }
            : u
        )
      );

      showToastNotification(result.message || 'Warning removed successfully', 'success');
    } catch (error) {
      showToastNotification(error.message || 'Failed to remove warning', 'error');
    }
  };

  const handleConfirmBan = async () => {
    if (!banModal.user) return;

    setIsBanLoading(true);

    try {
      const result = await userManagementService.banUser(banModal.user.userId);

      // Update user in state
      setUsers(prevUsers =>
        prevUsers.map(u =>
          u.userId === banModal.user.userId
            ? { ...u, isBanned: true }
            : u
        )
      );

      showToastNotification(
        result.message || `${banModal.user.profile?.fullName || banModal.user.email} has been banned`,
        'success'
      );

      setBanModal({ isOpen: false, user: null });
    } catch (error) {
      showToastNotification(error.message || 'Failed to ban user', 'error');
    } finally {
      setIsBanLoading(false);
    }
  };

  const handleClearFilters = () => {
    setSearchTerm("");
    setPeriod("all");
    setSearchBy("all");
    setSortBy("createdAt");
    setSortOrder("desc");
    setStatusFilter("all");
  };

  const handleSortChange = (column) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(column);
      setSortOrder("desc");
    }
  };

  const handleWarningSubmit = async (warningData) => {
    try {
      const result = await userManagementService.createWarning(warningModal.user.userId, warningData);

      // Update user in state
      setUsers(prevUsers =>
        prevUsers.map(u =>
          u.userId === warningModal.user.userId
            ? {
              ...u,
              warningCount: result.warningCount,
              isBanned: result.isBanned
            }
            : u
        )
      );

      showToastNotification(result.message || "Warning created successfully", "success");
      setWarningModal({ isOpen: false, user: null });
    } catch (err) {
      showToastNotification(err.message || "Failed to create warning", "error");
    }
  };

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-600"></div>
          <span className="ml-2 text-gray-600">Loading sellers...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <Title level={2} className="text-3xl font-bold text-gray-900">
          Manage Seller
        </Title>

        <div className="relative">
          <button className="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded-full flex items-center gap-2 transition-colors duration-200">
            Create auction
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>
      </div>

      {/* Filters */}
      <UserManagementFilters
        searchTerm={searchTerm}
        setSearchTerm={setSearchTerm}
        period={period}
        setPeriod={setPeriod}
        searchBy={searchBy}
        setSearchBy={setSearchBy}
        sortBy={sortBy}
        setSortBy={setSortBy}
        sortOrder={sortOrder}
        setSortOrder={setSortOrder}
        statusFilter={statusFilter}
        setStatusFilter={setStatusFilter}
        onClearFilters={handleClearFilters}
      />

      {/* Error Message */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
          <p className="text-red-800">{error}</p>
        </div>
      )}

      {/* Users Table */}
      <UserManagementTable
        users={filteredUsers}
        onCreateWarning={handleCreateWarning}
        onBanUser={handleBanUser}
        onUnbanUser={handleUnbanUser}
        onViewWarnings={handleViewWarnings}
        userType="seller"
        sortBy={sortBy}
        sortOrder={sortOrder}
        onSortChange={handleSortChange}
      />

      {/* Pagination */}
      {users.length > 0 && (
        <Pagination
          currentPage={pagination.page}
          totalPages={pagination.totalPages}
          hasNext={pagination.hasNext}
          hasPrevious={pagination.hasPrevious}
          onPageChange={handlePageChange}
          totalItems={pagination.total}
          limit={pagination.limit}
        />
      )}

      {/* Empty State */}
      {!loading && filteredUsers.length === 0 && (
        <div className="text-center py-12">
          <Title level={3} className="text-xl font-medium text-gray-900 mb-2">
            No sellers found
          </Title>
          <p className="text-gray-600 mb-6">
            {searchTerm ? "Try adjusting your search criteria" : "No sellers are currently registered"}
          </p>
        </div>
      )}

      {/* Modals */}
      <WarningModal
        isOpen={warningModal.isOpen}
        onClose={() => setWarningModal({ isOpen: false, user: null })}
        onSubmit={handleWarningSubmit}
        user={warningModal.user}
      />

      <ConfirmBanModal
        isOpen={banModal.isOpen}
        onClose={() => setBanModal({ isOpen: false, user: null })}
        onConfirm={handleConfirmBan}
        user={banModal.user}
        isLoading={isBanLoading}
      />

      <ViewWarningsModal
        isOpen={viewWarningsModal.isOpen}
        onClose={() => setViewWarningsModal({ isOpen: false, user: null, warnings: null })}
        user={viewWarningsModal.user}
        warnings={viewWarningsModal.warnings}
        onRemoveWarning={handleRemoveWarning}
        isLoading={isViewWarningsLoading}
      />
    </div>
  );
};

export default SellerManagement;
