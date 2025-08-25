import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useWallet } from '@/contexts/WalletContext';
import { useUser } from '@/contexts/UserContext';
import { FaWallet, FaPlus } from 'react-icons/fa';

export const WalletButton = ({ isHomePage }) => {
  const navigate = useNavigate();
  const { balance, formattedBalance, loading } = useWallet();
  const { user } = useUser();

  const handleAddFunds = () => {
    navigate('/wallet/add-funds');
  };

  const handleViewWallet = () => {
    navigate('/wallet');
  };

  const textColor = !isHomePage ? "text-black" : "text-white";
  const bgColor = !isHomePage ? "bg-gray-100 hover:bg-gray-200" : "bg-white/20 hover:bg-white/30";
  const buttonBg = !isHomePage ? "bg-green-500 hover:bg-green-600" : "bg-green-600 hover:bg-green-700";

  return (
    <div className="flex items-center gap-2">
      {/* Wallet Balance Display */}
      <div
        onClick={handleViewWallet}
        className={`flex items-center ${bgColor} ${textColor} px-3 py-2 rounded-lg cursor-pointer transition-all shadow-sm hover:scale-105`}
        title="View Wallet"
      >
        <FaWallet className="w-4 h-4 mr-2" />
        <div className="flex flex-col">
          <span className="text-xs opacity-80">Balance</span>
          <span className="font-semibold text-sm">
            {loading ? '...' : `${formattedBalance || '$0.00'}`}
          </span>
        </div>
      </div>

      {/* Add Funds Button */}
      <button
        onClick={handleAddFunds}
        className={`flex items-center ${buttonBg} text-white px-3 py-2 rounded-lg transition-colors shadow-sm hover:scale-105`}
        title="Add Funds"
      >
        <FaPlus className="w-4 h-4 mr-1" />
        <span className="font-medium text-sm">Add Funds</span>
      </button>
    </div>
  );
};

export default WalletButton;
