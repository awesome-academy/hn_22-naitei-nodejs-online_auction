import { IoCheckmarkCircleOutline, IoCloseCircleOutline, IoTimeOutline, IoPlayOutline, IoPauseOutline, IoStopOutline } from "react-icons/io5";

export const AUCTION_STATUS = {
    PENDING: 'PENDING',
    READY: 'READY',
    OPEN: 'OPEN',
    CLOSED: 'CLOSED',
    CANCELED: 'CANCELED',
    COMPLETED: 'COMPLETED'
};

export const AUCTION_STATUS_CONFIG = {
    [AUCTION_STATUS.PENDING]: {
        bg: "bg-amber-100",
        text: "text-amber-800",
        label: "Pending",
        icon: IoTimeOutline,
        tooltip: "Auction is pending approval"
    },
    [AUCTION_STATUS.READY]: {
        bg: "bg-sky-100",
        text: "text-sky-800",
        label: "Ready",
        icon: IoPauseOutline,
        tooltip: "Auction is ready to start"
    },
    [AUCTION_STATUS.OPEN]: {
        bg: "bg-emerald-100",
        text: "text-emerald-800",
        label: "Open",
        icon: IoCheckmarkCircleOutline,
        tooltip: "Auction is currently active"
    },
    [AUCTION_STATUS.CLOSED]: {
        bg: "bg-slate-100",
        text: "text-slate-800",
        label: "Closed",
        icon: IoCloseCircleOutline,
        tooltip: "Auction has ended"
    },
    [AUCTION_STATUS.CANCELED]: {
        bg: "bg-rose-100",
        text: "text-rose-800",
        label: "Canceled",
        icon: IoCloseCircleOutline,
        tooltip: "Auction was canceled"
    },
    [AUCTION_STATUS.COMPLETED]: {
        bg: "bg-violet-100",
        text: "text-violet-800",
        label: "Completed",
        icon: IoPlayOutline,
        tooltip: "Auction has been completed"
    }
};

export const getAuctionStatusConfig = (status) => {
    return AUCTION_STATUS_CONFIG[status] || AUCTION_STATUS_CONFIG[AUCTION_STATUS.PENDING];
};
