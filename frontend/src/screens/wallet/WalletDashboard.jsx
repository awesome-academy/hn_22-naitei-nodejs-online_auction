import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useWallet } from '@/contexts/WalletContext';
import { useUser } from '@/contexts/UserContext';
import { FaWallet, FaPlus, FaHistory, FaArrowUp, FaArrowDown } from 'react-icons/fa';
import { Header } from '@/components/ui';

const WalletDashboard = () => {
  const navigate = useNavigate();
  const { balance, formattedBalance, loading, fetchBalance, fetchTransactions } = useWallet();
  const { user } = useUser();

  const [transactions, setTransactions] = useState([]);
  const [totalTransactions, setTotalTransactions] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [isLoadingTransactions, setIsLoadingTransactions] = useState(false);
  const [filter, setFilter] = useState({
    type: '',
    sortOrder: 'DESC',
    limit: 10
  });

  useEffect(() => {
    fetchBalance();
    loadTransactions();
  }, [user]);

  const loadTransactions = async (page = 1, newFilter = filter) => {
    setIsLoadingTransactions(true);
    try {
      const response = await fetchTransactions({
        page,
        limit: newFilter.limit,
        type: newFilter.type || undefined,
        sortOrder: newFilter.sortOrder
      });

      setTransactions(response.transactions || []);
      setTotalTransactions(response.total || 0);
      setCurrentPage(page);
    } catch (error) {
      console.error('Failed to load transactions:', error);
    } finally {
      setIsLoadingTransactions(false);
    }
  };

  const handleFilterChange = (newFilter) => {
    setFilter(prev => ({ ...prev, ...newFilter }));
    loadTransactions(1, { ...filter, ...newFilter });
  };

  const handlePageChange = (page) => {
    loadTransactions(page);
  };

  const getTransactionIcon = (type, status) => {
    if (status === 'FAILED') return <FaArrowDown className="text-red-500" />;
    switch (type) {
      case 'DEPOSIT':
        return <FaArrowUp className="text-green-500" />;
      case 'WITHDRAWAL':
        return <FaArrowDown className="text-orange-500" />;
      case 'BID_PAYMENT':
        return <FaArrowDown className="text-blue-500" />;
      case 'BID_REFUND':
        return <FaArrowUp className="text-purple-500" />;
      default:
        return <FaHistory className="text-gray-500" />;
    }
  };

  const getTransactionTypeText = (type) => {
    const typeMap = {
      'DEPOSIT': 'Deposit',
      'WITHDRAWAL': 'Withdraw',
      'BID_PAYMENT': 'Auction Payment',
      'BID_REFUND': 'Auction Refund',
      'ADMIN_ADJUSTMENT': 'Admin Adjustment'
    };
    return typeMap[type] || type;
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'SUCCESS': return 'text-green-600 bg-green-50';
      case 'PENDING': return 'text-yellow-600 bg-yellow-50';
      case 'FAILED': return 'text-red-600 bg-red-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const formatUSD = (n) => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(n);

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const totalPages = Math.ceil(totalTransactions / filter.limit);

  return (
    <>
      <Header />
      <div className="min-h-screen bg-gray-50">
        <div className="container mx-auto px-4 py-8">
          <div className="max-w-6xl mx-auto">
            {/* Header Section */}
            <div className="mb-8">
              <div className="flex items-center justify-between mb-4">
                <h1 className="text-3xl font-bold text-gray-800 flex items-center">
                  <FaWallet className="mr-3 text-blue-600" />
                  My Wallet
                </h1>
                <button
                  onClick={() => navigate('/wallet/add-funds')}
                  className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center shadow-md"
                >
                  <FaPlus className="mr-2" />
                  Add Funds
                </button>
              </div>
            </div>

            {/* Balance Card */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              {/* Main Balance */}
              <div className="md:col-span-2 bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-xl p-6 shadow-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-blue-100 text-sm mb-2">Current Balance</p>
                    <p className="text-4xl font-bold mb-2">
                      {loading ? '...' : formattedBalance || formatUSD(0)}
                    </p>
                    <p className="text-blue-100 text-sm">
                      Last updated: {new Date().toLocaleString('en-US')}
                    </p>
                  </div>
                  <div className="text-6xl text-blue-300 opacity-50">
                    <FaWallet />
                  </div>
                </div>
              </div>

              {/* Quick Actions */}
              <div className="bg-white rounded-xl p-6 shadow-md">
                <h3 className="font-semibold text-gray-800 mb-4">Quick Actions</h3>
                <div className="space-y-3">
                  <button
                    onClick={() => navigate('/wallet/add-funds')}
                    className="w-full bg-red-500 text-black py-3 rounded-lg hover:bg-red-600 transition-colors flex items-center justify-center"
                  >
                    <FaPlus className="mr-2" />
                    Add Funds
                  </button>
                  <button
                    onClick={() => window.location.reload()}
                    className="w-full bg-gray-500 text-white py-3 rounded-lg hover:bg-gray-600 transition-colors flex items-center justify-center"
                  >
                    <FaHistory className="mr-2" />
                    Refresh
                  </button>
                </div>
              </div>
            </div>

            {/* Transaction History */}
            <div className="bg-white rounded-xl shadow-md overflow-hidden">
              {/* Header */}
              <div className="bg-gray-50 px-6 py-4 border-b">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-semibold text-gray-800 flex items-center">
                    <FaHistory className="mr-2" />
                    Transaction History
                  </h2>
                  <div className="flex items-center gap-4">
                    {/* Filter */}
                    <select
                      value={filter.type}
                      onChange={(e) => handleFilterChange({ type: e.target.value })}
                      className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="">All Types</option>
                      <option value="DEPOSIT">Deposit</option>
                      <option value="WITHDRAWAL">Withdraw</option>
                      <option value="BID_PAYMENT">Auction Payment</option>
                      <option value="BID_REFUND">Auction Refund</option>
                    </select>

                    {/* Sort Order */}
                    <select
                      value={filter.sortOrder}
                      onChange={(e) => handleFilterChange({ sortOrder: e.target.value })}
                      className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="DESC">Newest</option>
                      <option value="ASC">Oldest</option>
                    </select>

                    {/* Limit */}
                    <select
                      value={filter.limit}
                      onChange={(e) => handleFilterChange({ limit: parseInt(e.target.value) })}
                      className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value={10}>10 / page</option>
                      <option value={20}>20 / page</option>
                      <option value={50}>50 / page</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Transaction List */}
              <div className="divide-y divide-gray-200">
                {isLoadingTransactions ? (
                  <div className="p-8 text-center">
                    <div className="inline-block w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                    <p className="mt-2 text-gray-500">Loading transactions...</p>
                  </div>
                ) : transactions.length === 0 ? (
                  <div className="p-8 text-center">
                    <FaHistory className="mx-auto text-4xl text-gray-300 mb-4" />
                    <p className="text-gray-500">No transactions yet</p>
                  </div>
                ) : (
                  transactions.map((transaction) => (
                    <div key={transaction.transactionId} className="p-6 hover:bg-gray-50 transition-colors">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center">
                          <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center mr-4">
                            {getTransactionIcon(transaction.type, transaction.status)}
                          </div>
                          <div>
                            <p className="font-semibold text-gray-800">
                              {getTransactionTypeText(transaction.type)}
                            </p>
                            <p className="text-sm text-gray-500">
                              {formatDate(transaction.createdAt)}
                            </p>
                            {transaction.description && (
                              <p className="text-sm text-gray-600 mt-1">
                                {transaction.description}
                              </p>
                            )}
                            {transaction.auction && (
                              <p className="text-sm text-blue-600 mt-1">
                                Auction: {transaction.auction.title}
                              </p>
                            )}
                          </div>
                        </div>
                        <div className="text-right">
                          <p className={`font-bold text-lg ${
                            transaction.type === 'DEPOSIT' || transaction.type === 'BID_REFUND'
                              ? 'text-green-600'
                              : 'text-red-600'
                          }`}>
                            {transaction.type === 'DEPOSIT' || transaction.type === 'BID_REFUND' ? '+' : '-'}
                            {formatUSD(Number(transaction.amount))}
                          </p>
                          <div className="flex items-center justify-end mt-1 gap-2">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(transaction.status)}`}>
                              {transaction.status === 'SUCCESS' ? 'Success' :
                               transaction.status === 'PENDING' ? 'Pending' : 'Failed'}
                            </span>
                          </div>
                          <p className="text-sm text-gray-500 mt-1">
                            Balance: {formatUSD(Number(transaction.balanceAfter))}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="bg-gray-50 px-6 py-4 border-t">
                  <div className="flex items-center justify-between">
                    <p className="text-sm text-gray-700">
                      Showing {((currentPage - 1) * filter.limit) + 1} - {Math.min(currentPage * filter.limit, totalTransactions)}
                      of {totalTransactions} transactions
                    </p>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handlePageChange(currentPage - 1)}
                        disabled={currentPage === 1}
                        className="px-3 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        Previous
                      </button>

                      {[...Array(Math.min(5, totalPages))].map((_, index) => {
                        let pageNumber;
                        if (totalPages <= 5) {
                          pageNumber = index + 1;
                        } else if (currentPage <= 3) {
                          pageNumber = index + 1;
                        } else if (currentPage >= totalPages - 2) {
                          pageNumber = totalPages - 4 + index;
                        } else {
                          pageNumber = currentPage - 2 + index;
                        }

                        return (
                          <button
                            key={pageNumber}
                            onClick={() => handlePageChange(pageNumber)}
                            className={`px-3 py-2 border rounded-lg text-sm font-medium ${
                              currentPage === pageNumber
                                ? 'bg-blue-600 text-white border-blue-600'
                                : 'border-gray-300 text-gray-700 hover:bg-gray-50'
                            }`}
                          >
                            {pageNumber}
                          </button>
                        );
                      })}

                      <button
                        onClick={() => handlePageChange(currentPage + 1)}
                        disabled={currentPage === totalPages}
                        className="px-3 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        Next
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default WalletDashboard;
