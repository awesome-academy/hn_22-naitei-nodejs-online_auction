import React from "react";

const AuctionManagementFilters = ({
    searchTerm,
    setSearchTerm,
    period,
    setPeriod,
    searchBy,
    setSearchBy,
    sortBy,
    setSortBy,
    sortOrder,
    setSortOrder,
    statusFilter,
    setStatusFilter,
    onClearFilters,
}) => {
    const searchOptions = [
        { value: "title", label: "Title" },
        { value: "seller", label: "Seller" },
        { value: "auctionId", label: "Auction ID" },
    ];

    const periodOptions = [
        { value: "", label: "All Time" },
        { value: "today", label: "Today" },
        { value: "week", label: "This Week" },
        { value: "month", label: "This Month" },
        { value: "year", label: "This Year" },
    ];

    const sortOptions = [
        { value: "createdAt", label: "Created Date" },
        { value: "startTime", label: "Start Time" },
        { value: "endTime", label: "End Time" },
        { value: "startingPrice", label: "Starting Price" },
        { value: "title", label: "Title" },
    ];

    const statusOptions = [
        { value: "", label: "All Status" },
        { value: "PENDING", label: "Pending" },
        { value: "READY", label: "Ready" },
        { value: "OPEN", label: "Open" },
        { value: "CLOSED", label: "Closed" },
        { value: "CANCELED", label: "Canceled" },
    ];

    return (
        <div className="bg-white border border-gray-200 rounded-lg p-6 mb-6">
            {/* Search */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                        Search
                    </label>
                    <input
                        type="text"
                        placeholder="Search auctions..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent"
                    />
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                        Search By
                    </label>
                    <select
                        value={searchBy}
                        onChange={(e) => setSearchBy(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent"
                    >
                        {searchOptions.map((option) => (
                            <option key={option.value} value={option.value}>
                                {option.label}
                            </option>
                        ))}
                    </select>
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                        Status
                    </label>
                    <select
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent"
                    >
                        {statusOptions.map((option) => (
                            <option key={option.value} value={option.value}>
                                {option.label}
                            </option>
                        ))}
                    </select>
                </div>
            </div>

            {/* Filters */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                        Period
                    </label>
                    <select
                        value={period}
                        onChange={(e) => setPeriod(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent"
                    >
                        {periodOptions.map((option) => (
                            <option key={option.value} value={option.value}>
                                {option.label}
                            </option>
                        ))}
                    </select>
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                        Sort By
                    </label>
                    <select
                        value={sortBy}
                        onChange={(e) => setSortBy(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent"
                    >
                        {sortOptions.map((option) => (
                            <option key={option.value} value={option.value}>
                                {option.label}
                            </option>
                        ))}
                    </select>
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                        Sort Order
                    </label>
                    <select
                        value={sortOrder}
                        onChange={(e) => setSortOrder(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent"
                    >
                        <option value="desc">Descending</option>
                        <option value="asc">Ascending</option>
                    </select>
                </div>

                <div className="flex items-end">
                    <button
                        onClick={onClearFilters}
                        className="w-full px-4 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors duration-200"
                    >
                        Clear Filters
                    </button>
                </div>
            </div>
        </div>
    );
};

export default AuctionManagementFilters;
