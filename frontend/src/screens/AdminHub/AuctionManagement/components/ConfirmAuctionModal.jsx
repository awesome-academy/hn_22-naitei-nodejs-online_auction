import React from "react";
import { IoCloseOutline, IoCheckmarkCircleOutline } from "react-icons/io5";
import "./modalStyles.css";

const ConfirmAuctionModal = ({
    isOpen,
    onClose,
    auction,
    onConfirm,
    loading = false,
}) => {
    if (!isOpen || !auction) return null;

    const handleSubmit = (e) => {
        e.preventDefault();
        onConfirm();
    };

    return (
        <div className="modalBackdrop">
            <div className="modalContent">
                {/* Header */}
                <div className="modalHeader">
                    <div className="modalTitle">
                        <div className="iconContainer">
                            <IoCheckmarkCircleOutline className="greenIcon" size={20} />
                        </div>
                        <h3 className="heading">
                            Confirm Auction
                        </h3>
                    </div>
                    <button
                        onClick={onClose}
                        className="closeButton"
                        disabled={loading}
                    >
                        <IoCloseOutline size={20} />
                    </button>
                </div>

                {/* Content */}
                <div className="modalBody">
                    <div style={{ marginBottom: '1.5rem' }}>
                        <p style={{
                            color: '#374151',
                            marginBottom: '0.5rem'
                        }}>
                            You are about to confirm and open the auction:
                            <span style={{ fontWeight: '600' }}> "{auction?.title}"</span>
                        </p>
                        <p style={{
                            fontSize: '0.875rem',
                            color: '#6b7280',
                            marginBottom: '1rem'
                        }}>
                            This will change the auction status from PENDING to READY/OPEN and make it available for bidders.
                        </p>

                        {/* Auction Details Summary */}
                        <div style={{
                            backgroundColor: '#f9fafb',
                            borderRadius: '0.5rem',
                            padding: '1rem',
                        }}>
                            <div style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                marginBottom: '0.5rem'
                            }}>
                                <span style={{ fontSize: '0.875rem', color: '#4b5563' }}>Auction ID:</span>
                                <span style={{ fontSize: '0.875rem', fontWeight: '500', color: '#111827' }}>{auction?.auctionId}</span>
                            </div>
                            <div style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                marginBottom: '0.5rem'
                            }}>
                                <span style={{ fontSize: '0.875rem', color: '#4b5563' }}>Seller:</span>
                                <span style={{ fontSize: '0.875rem', fontWeight: '500', color: '#111827' }}>
                                    {auction?.sellerName || auction?.sellerEmail || auction?.seller?.profile?.fullName || auction?.seller?.email || 'Unknown'}
                                </span>
                            </div>
                            <div style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                marginBottom: '0.5rem'
                            }}>
                                <span style={{ fontSize: '0.875rem', color: '#4b5563' }}>Starting Price:</span>
                                <span style={{ fontSize: '0.875rem', fontWeight: '500', color: '#111827' }}>
                                    {auction?.startingPrice ? new Intl.NumberFormat('vi-VN', {
                                        style: 'currency',
                                        currency: 'VND'
                                    }).format(auction.startingPrice) : 'N/A'}
                                </span>
                            </div>
                            <div style={{
                                display: 'flex',
                                justifyContent: 'space-between'
                            }}>
                                <span style={{ fontSize: '0.875rem', color: '#4b5563' }}>Start Time:</span>
                                <span style={{ fontSize: '0.875rem', fontWeight: '500', color: '#111827' }}>
                                    {auction?.startTime ? new Date(auction.startTime).toLocaleString('vi-VN') : 'N/A'}
                                </span>
                            </div>
                        </div>
                    </div>

                    <div style={{
                        backgroundColor: '#eff6ff',
                        border: '1px solid #bfdbfe',
                        borderRadius: '0.5rem',
                        padding: '1rem',
                        marginBottom: '1.5rem'
                    }}>
                        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                            <div style={{
                                width: '0.25rem',
                                height: '0.25rem',
                                backgroundColor: '#3b82f6',
                                borderRadius: '9999px',
                                marginTop: '0.5rem',
                                flexShrink: 0
                            }}></div>
                            <div>
                                <p style={{
                                    fontSize: '0.875rem',
                                    color: '#1e40af',
                                    fontWeight: '500',
                                    marginBottom: '0.25rem'
                                }}>Important Note:</p>
                                <p style={{ fontSize: '0.875rem', color: '#1e3a8a' }}>
                                    Once confirmed, the auction will be live and bidders can start placing bids.
                                    Make sure all auction details are correct before confirming.
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Actions */}
                    <div className="actionButtons">
                        <button
                            type="button"
                            onClick={onClose}
                            disabled={loading}
                            className="cancelButton"
                        >
                            Cancel
                        </button>
                        <button
                            type="button"
                            onClick={handleSubmit}
                            disabled={loading}
                            className="confirmButton"
                        >
                            {loading ? (
                                <>
                                    <div className="spinner"></div>
                                    <span className="whiteText">Confirming...</span>
                                </>
                            ) : (
                                <>
                                    <IoCheckmarkCircleOutline size={16} className="whiteText" />
                                    <span className="whiteText">Confirm Auction</span>
                                </>
                            )}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ConfirmAuctionModal;
