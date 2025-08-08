import { Routes, Route } from "react-router-dom";
import CreateAuction from "@/screens/auctions/CreateAuction/index.jsx";

export const AuctionRoutes = () => {
    return (
        <Routes>
            <Route path="create" element={<CreateAuction />} />
        </Routes>
    );
};
