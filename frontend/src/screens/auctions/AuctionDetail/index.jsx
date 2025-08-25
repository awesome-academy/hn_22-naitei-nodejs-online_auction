import { Layout } from "@/components/layout/Layout.jsx";
import { Caption, Container, LoadingSpinner, PrimaryButton, Title } from "@/components/ui/index.js";
import { useNotification } from "@/contexts/NotificationContext.jsx";
import { useUser } from "@/contexts/UserContext.jsx";
import { auctionService } from "@/services/auction.service.js";
import { bidService } from "@/services/bid.service.js";
import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

const statusBadgeClass = (status) => ({
  PENDING: "text-gray-700 bg-yellow-400",
  READY: "text-blue-700 bg-blue-200",
  OPEN: "text-white bg-green",
  CLOSED: "text-gray-700 bg-gray-200",
  CANCELED: "text-red-700 bg-red-200",
  COMPLETED: "text-blue-500 bg-slate-200",
  EXTENDED: "text-orange-700 bg-orange-200",
}[status] || "text-black bg-white");

const formatMoney = (n) => {
  const num = Number(n || 0);
  return num.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
};

const useCountdown = (end) => {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  const endTime = end ? new Date(end) : null;
  const timeLeft = endTime ? Math.max(0, endTime - now) : 0;
  const isOver = timeLeft <= 0;
  const days = isOver ? 0 : Math.floor(timeLeft / (1000 * 60 * 60 * 24));
  const hours = isOver ? 0 : Math.floor((timeLeft / (1000 * 60 * 60)) % 24);
  const minutes = isOver ? 0 : Math.floor((timeLeft / (1000 * 60)) % 60);
  const seconds = isOver ? 0 : Math.floor((timeLeft / 1000) % 60);
  return { days, hours, minutes, seconds, isOver, timeLeftMs: timeLeft };
};

const AuctionDetail = () => {
  const { auctionId } = useParams();
  const { user } = useUser();
  const { showToastNotification } = useNotification();

  const [auction, setAuction] = useState(null);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const { days, hours, minutes, seconds, isOver, timeLeftMs } = useCountdown(auction?.endTime);

  const canBidStatus = auction?.status === "OPEN" || auction?.status === "EXTENDED";
  const isSellerOwner = user && auction && user.id === auction.sellerId;
  const isSeller = user && auction && user.role === "SELLER";
  const isAdmin = user && auction && user.role === "ADMIN";
  const canBid = user && user.role === "BIDDER" && !isSellerOwner && !isSeller && canBidStatus && !isOver;

  const isLast10Min = canBidStatus && timeLeftMs > 0 && timeLeftMs <= 10 * 60 * 1000;

  // Bid input
  const minBid = useMemo(() => {
    const current = Number(auction?.currentPrice || 0);
    const step = Number(auction?.minimumBidIncrement || 0);
    return current + step;
  }, [auction]);

  const [bidInput, setBidInput] = useState("");
  const [hiddenInputs, setHiddenInputs] = useState(["", "", ""]);

  useEffect(() => {
    setBidInput(minBid ? String(minBid) : "");
  }, [minBid]);

  // Auto-switch to hidden bid mode in last 10 minutes
  useEffect(() => {
    if (isLast10Min && !isSellerOwner && canBid) {
      // Clear normal bid input and focus on hidden bids
      setBidInput("");
      // Show notification about auto-switching
      showToastNotification("Last 10 minutes: Switched to hidden bid mode", "info");
    }
  }, [isLast10Min, isSellerOwner, canBid, showToastNotification]);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      setLoading(true);
      setFetchError(null);
      try {
        const data = await auctionService.getAuctionById(auctionId);
        if (mounted) setAuction(data);
      } catch (err) {
        if (mounted) setFetchError(err?.message || "Failed to load auction");
      } finally {
        if (mounted) setLoading(false);
      }
    };
    load();
    return () => {
      mounted = false;
    };
  }, [auctionId]);

  const refreshAuction = async () => {
    try {
      const data = await auctionService.getAuctionById(auctionId);
      setAuction(data);
    } catch (e) {
      // keep old state on refresh error
    }
  };

  const handlePlaceBid = async () => {
    if (!canBid) return;

    const confirmMsg = isLast10Min
      ? "Are you sure you want to submit hidden bids?"
      : `Are you sure you want to place a bid of $${formatMoney(bidInput)}?`;
    if (!window.confirm(confirmMsg)) return;

    try {
      setSubmitting(true);
      if (!isLast10Min) {
        const amount = Number(bidInput);
        const step = Number(auction?.minimumBidIncrement || 0);
        const current = Number(auction?.currentPrice || 0);

        if (!amount || amount < minBid) {
          showToastNotification(`Minimum bid: $${formatMoney(minBid)}`, "error");
          return;
        }

        // robust multiple-of-increment check using cents
        const toCents = (n) => Math.round(Number(n) * 100);
        const diffCents = toCents(amount) - toCents(current);
        const stepCents = toCents(step);
        if (stepCents > 0 && diffCents % stepCents !== 0) {
          showToastNotification(
            `Bid must be a multiple of the increment ($${formatMoney(step)})`,
            "error"
          );
          return;
        }

        await bidService.placeBid({ auctionId, bidAmount: amount });
        showToastNotification("Bid placed successfully", "success");
        await refreshAuction();
        setBidInput(String(Number(auction?.currentPrice || 0) + Number(auction?.minimumBidIncrement || 0)));
      } else {
        const values = hiddenInputs
          .map((v) => Number(v))
          .filter((v) => Number.isFinite(v) && v > 0);

        if (values.length === 0) {
          showToastNotification("Please enter at least 1 hidden bid amount", "error");
          return;
        }
        if (values.length > 3) {
          showToastNotification("You can enter up to 3 hidden bid amounts only", "error");
          return;
        }
        await bidService.placeHiddenBids({ auctionId, bidAmounts: values });
        showToastNotification("Hidden bids submitted successfully", "success");
        await refreshAuction();
        setHiddenInputs(["", "", ""]);
      }
    } catch (err) {
      let errorMessage = "Failed to place bid";

      if (err?.response?.data?.message) {
        errorMessage = err.response.data.message;
      } else if (err?.response?.data?.errorCode) {
        errorMessage = err.response.data.message || `Error: ${err.response.data.errorCode}`;
      } else if (err?.message) {
        errorMessage = err.message;
      } else if (err?.statusCode === 400) {
        errorMessage = "Invalid bid request. Please check your input.";
      } else if (err?.statusCode === 401) {
        errorMessage = "Please log in to place a bid.";
      } else if (err?.statusCode === 403) {
        errorMessage = "You don't have permission to place bids.";
      } else if (err?.statusCode === 404) {
        errorMessage = "Auction not found.";
      } else if (err?.statusCode >= 500) {
        errorMessage = "Server error. Please try again later.";
      }

      showToastNotification(errorMessage, "error");
      console.error('Bid placement error:', err);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <Layout>
        <LoadingSpinner text="Loading auction..." />
      </Layout>
    );
  }

  if (fetchError || !auction) {
    return (
      <Layout>
        <Container className="py-8">
          <div className="text-center">
            <Title level={2} className="text-gray-900 mb-4">Auction not found</Title>
            <p className="text-gray-600">{fetchError || "We couldn't load this auction."}</p>
          </div>
        </Container>
      </Layout>
    );
  }

  const products = auction.products || [];
  const bids = auction.bids || [];

  return (
    <Layout>
      <Container className="py-8">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
          <div>
            <Title level={2} className="text-gray-900 mb-2">{auction.title}</Title>
            <div className="flex items-center gap-3">
              <Caption className={`px-3 py-1 text-sm rounded-full ${statusBadgeClass(auction.status)}`}>
                {auction.status}
              </Caption>
              <Caption className="text-green bg-green_100 px-3 py-1 text-sm rounded-full">
                Current: ${formatMoney(auction.currentPrice)}
              </Caption>
              <Caption className="text-gray-700 bg-gray-100 px-3 py-1 text-sm rounded-full">
                Min increment: ${formatMoney(auction.minimumBidIncrement)}
              </Caption>
            </div>
          </div>
          <div className="text-right">
            <Caption className="text-green">Time left</Caption>
            <Title>
              {days}d : {hours}h : {minutes}m : {seconds}s
            </Title>
          </div>
        </div>

        {/* Seller */}
        <div className="bg-white rounded-lg shadow p-4 mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-gray-200 flex items-center justify-center">
                <svg className="w-5 h-5 text-gray-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clipRule="evenodd" />
                </svg>
              </div>
              <div>
                <Caption className="text-gray-600">Seller</Caption>
                <Title level={4} className="text-gray-900">{auction.sellerName || "Unknown"}</Title>
              </div>
            </div>
            {!isSellerOwner && (
              <Link to={`/seller/${auction.sellerId}`} className="text-green hover:underline">
                View seller profile
              </Link>
            )}
          </div>
        </div>

        {/* Content grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Images & Products */}
          <div className="lg:col-span-2">
            <div className="bg-white rounded-lg shadow p-4 mb-6">
              <Title level={4} className="mb-4">Products</Title>
              {products.length === 0 ? (
                <Caption className="text-gray-600">No products attached.</Caption>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {products.map((p) => (
                    <div key={p.productId} className="border rounded-lg overflow-hidden">
                      {p.images && p.images.length > 0 ? (
                        <img
                          src={p.images[0]}
                          alt={p.name}
                          className="w-full h-56 object-cover"
                        />
                      ) : (
                        <div className="w-full h-56 bg-gray-100 flex items-center justify-center">
                          <span className="text-gray-400">No image</span>
                        </div>
                      )}
                      <div className="p-3">
                        <div className="font-semibold text-gray-900 mb-1">{p.name}</div>
                        {p.description && (
                          <div className="text-sm text-gray-600 line-clamp-2">{p.description}</div>
                        )}
                        <div className="mt-2 text-sm text-gray-700">Qty: {p.quantity}</div>
                        {p.categories && p.categories.length > 0 && (
                          <div className="mt-2">
                            <Caption className="text-gray-600">Categories:</Caption>
                            <div className="flex flex-wrap gap-2 mt-1">
                              {p.categories.map((c) => (
                                <span key={c} className="px-2 py-1 text-xs bg-gray-100 rounded-full">{c}</span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Bid history */}
            <div className="bg-white rounded-lg shadow p-4">
              <Title level={4} className="mb-4">Bid history</Title>
              {bids.length === 0 ? (
                <Caption className="text-gray-600">No bids yet.</Caption>
              ) : (
                <div className="space-y-3">
                  {bids.map((b) => (
                    <div key={b.bidId} className="flex items-center justify-between border-b pb-3">
                      <div>
                        <div className="font-medium text-gray-900">{b.bidderName}</div>
                        <Caption className="text-gray-600">{new Date(b.createdAt).toLocaleString()}</Caption>
                      </div>
                      <div className="text-right">
                        <Caption className="text-gray-600">Bid</Caption>
                        <Title level={4}>${formatMoney(b.bidAmount)}</Title>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

                    {/* Right: Place bid */}
                    <div className="lg:col-span-1">
            <div className="bg-white rounded-lg shadow p-4 sticky top-24">
              <Title level={4} className="mb-2">
                {isLast10Min ? "Hidden Bids (Last 10 minutes)" : "Place a bid"}
              </Title>

              {/* Warning banner for last 10 minutes */}
              {isLast10Min && (
                <div className="bg-orange-50 border border-orange-200 rounded-lg p-3 mb-4">
                  <div className="flex items-center">
                    <svg className="w-5 h-5 text-orange-600 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.987-.833-2.764 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                    <span className="text-orange-800 text-sm font-medium">
                      Last 10 minutes - Hidden bid mode activated
                    </span>
                  </div>
                </div>
              )}

              {!isLast10Min ? (
                <>
                  <Caption className="text-gray-600 mb-4 block">
                    Minimum allowed: ${formatMoney(minBid)}
                  </Caption>
                  <input
                    type="number"
                    min={minBid}
                    step={auction?.minimumBidIncrement || 1}
                    value={bidInput}
                    onChange={(e) => setBidInput(e.target.value)}
                    className="w-full p-3 border border-gray-200 rounded mb-4 outline-none focus:ring-2 focus:ring-green"
                  />
                </>
              ) : (
                <>
                  <Caption className="text-gray-600 mb-4 block">
                    Enter up to 3 hidden bid amounts (can leave blank).
                  </Caption>
                  <div className="space-y-2 mb-4">
                    {hiddenInputs.map((v, i) => (
                      <input
                        key={i}
                        type="number"
                        min={1}
                        step={auction?.minimumBidIncrement || 1}
                        value={v}
                        onChange={(e) => {
                          const next = [...hiddenInputs];
                          next[i] = e.target.value;
                          setHiddenInputs(next);
                        }}
                        placeholder={`Hidden bid #${i + 1}`}
                        className="w-full p-3 border border-gray-200 rounded outline-none focus:ring-2 focus:ring-green"
                      />
                    ))}
                  </div>
                </>
              )}

              <PrimaryButton
                className="w-full py-3 rounded-lg"
                onClick={handlePlaceBid}
                disabled={!canBid || submitting || (!isLast10Min && Number(bidInput) < minBid)}
              >
                {submitting ? "Submitting..." : canBid ? (isLast10Min ? "Submit Hidden Bids" : "Place Bid") : "Bidding not available"}
              </PrimaryButton>

              {!user && (
                <Caption className="text-gray-600 mt-3 block">
                  Please log in as a bidder to place bids.
                </Caption>
              )}
              {(!canBidStatus || isOver) && (
                <Caption className="text-gray-600 mt-3 block">
                  Auction is not open for bidding.
                </Caption>
              )}
              {isAdmin && (
                <Caption className="text-gray-600 mt-3 block">
                  Admins cannot bid on any auction.
                </Caption>
              )}
              {isSeller && (
                <Caption className="text-gray-600 mt-3 block">
                  Sellers cannot bid on any auctions.
                </Caption>
              )}
            </div>
          </div>
        </div>
      </Container>
    </Layout>
  );
};

export default AuctionDetail;
