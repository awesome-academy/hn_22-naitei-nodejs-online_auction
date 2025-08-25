import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useWallet } from '../../contexts/WalletContext';
import qrCodeImage from '../../assets/images/qrcode.png';

const AddFunds = () => {
  const navigate = useNavigate();
  const { addFunds, loading } = useWallet();

  const [amount, setAmount] = useState('');
  const [description, setDescription] = useState('');
  const [showPayment, setShowPayment] = useState(false);
  const [bankInfo, setBankInfo] = useState(null);

  const presetAmounts = [100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000];

  const formatUSD = (value) => {
    const n = Number(value || 0);
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(n);
  };

  const handleAmountChange = (e) => {
    const value = e.target.value.replace(/[^\d]/g, '');
    setAmount(value);
  };

  const handlePresetClick = (presetAmount) => {
    setAmount(presetAmount.toString());
  };

  const generatePaymentInfo = () => {
    if (!amount || parseInt(amount) < 10) {
      alert('Minimum amount is $10.00');
      return;
    }

    if (parseInt(amount) > 10000) {
      alert('Maximum amount is $10,000.00');
      return;
    }

    const paymentInfo = {
      bankCode: 'MB',
      accountNumber: '0123456789',
      accountName: 'AUCTION HOUSE',
      amount: parseInt(amount),
      transferContent: `DEPOSIT ${Date.now()}`,
      transferCode: `DEP${Date.now().toString().slice(-6)}`
    };

    setBankInfo(paymentInfo);
    setShowPayment(true);
  };

  const handleConfirmPayment = async () => {
    try {
      await addFunds(
        parseInt(amount),
        description || `Deposit ${formatUSD(parseInt(amount))}`
      );
      navigate('/wallet');
    } catch (error) {
      console.error('Payment failed:', error);
    }
  };

  const handleBack = () => {
    if (showPayment) {
      setShowPayment(false);
    } else {
      navigate(-1);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      alert('Copied to clipboard!');
    });
  };

  if (showPayment) {
    return (
      <div className="min-h-screen bg-gray-50 py-8">
        <div className="container mx-auto px-4">
          <div className="max-w-lg mx-auto bg-white rounded-lg shadow-lg overflow-hidden">
            {/* Header */}
            <div className="bg-blue-600 text-white p-6">
              <div className="flex items-center justify-between">
                <h1 className="text-xl font-bold">Payment Information</h1>
                <button
                  onClick={handleBack}
                  className="text-white hover:text-gray-200"
                >
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>

            <div className="p-6">
             <div className="bg-gradient-to-br from-blue-50 to-blue-100 p-6 rounded-lg border-2 border-blue-200 mb-6 text-center">
                <div className="bg-white p-4 rounded-lg shadow-md inline-block">
                  {/* QR Code */}
                  <img
                    src={qrCodeImage}
                    alt="Payment QR Code"
                    className="w-48 h-48 mx-auto rounded-lg"
                    onError={(e) => {
                      e.target.style.display = 'none';
                      e.target.nextSibling.style.display = 'block';
                    }}
                  />
                  {/* Fallback content */}
                  <div style={{ display: 'none' }} className="w-48 h-48 flex items-center justify-center text-center">
                    <div>
                      <svg className="w-16 h-16 mx-auto text-blue-500 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h4m-6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h4" />
                      </svg>
                      <p className="text-blue-600 font-medium text-sm">QR Code</p>
                    </div>
                  </div>
                </div>
                <p className="text-blue-600 font-medium mt-4">Scan QR with your Banking App</p>
                <p className="text-sm text-blue-500 mt-2">Or use the transfer information below</p>
              </div>

              {/* Bank Info */}
              <div className="bg-gray-50 rounded-lg p-4 mb-6">
                <h3 className="font-semibold text-gray-800 mb-4 flex items-center">
                  <svg className="w-5 h-5 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 002 2z" />
                  </svg>
                  Bank Transfer Information
                </h3>
                <div className="space-y-3">
                  <div className="flex justify-between items-center bg-white p-3 rounded border">
                    <div>
                      <span className="text-sm text-gray-600">Bank:</span>
                      <p className="font-medium">MB Bank</p>
                    </div>
                    <button
                      onClick={() => copyToClipboard('MB Bank')}
                      className="text-blue-500 hover:text-blue-700"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>

                  <div className="flex justify-between items-center bg-white p-3 rounded border">
                    <div>
                      <span className="text-sm text-gray-600">Account Number:</span>
                      <p className="font-medium font-mono">{bankInfo?.accountNumber}</p>
                    </div>
                    <button
                      onClick={() => copyToClipboard(bankInfo?.accountNumber)}
                      className="text-blue-500 hover:text-blue-700"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>

                  <div className="flex justify-between items-center bg-white p-3 rounded border">
                    <div>
                      <span className="text-sm text-gray-600">Account Name:</span>
                      <p className="font-medium">{bankInfo?.accountName}</p>
                    </div>
                    <button
                      onClick={() => copyToClipboard(bankInfo?.accountName)}
                      className="text-blue-500 hover:text-blue-700"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>

                  <div className="flex justify-between items-center bg-yellow-50 p-3 rounded border border-yellow-200">
                    <div>
                      <span className="text-sm text-gray-600">Amount:</span>
                      <p className="font-bold text-lg text-red-600">{formatUSD(parseInt(amount))}</p>
                    </div>
                    <button
                      onClick={() => copyToClipboard(amount)}
                      className="text-blue-500 hover:text-blue-700"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>

                  <div className="flex justify-between items-center bg-white p-3 rounded border">
                    <div>
                      <span className="text-sm text-gray-600">Transfer Content:</span>
                      <p className="font-medium font-mono text-sm">{bankInfo?.transferContent}</p>
                    </div>
                    <button
                      onClick={() => copyToClipboard(bankInfo?.transferContent)}
                      className="text-blue-500 hover:text-blue-700"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>

              {/* Instructions */}
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
                <h4 className="font-semibold text-blue-800 mb-3 flex items-center">
                  <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Payment Instructions
                </h4>
                <ol className="text-sm text-blue-700 space-y-2">
                  <li className="flex items-start">
                    <span className="bg-blue-500 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs mr-2 mt-0.5">1</span>
                    Open your Banking or Internet Banking app
                  </li>
                  <li className="flex items-start">
                    <span className="bg-blue-500 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs mr-2 mt-0.5">2</span>
                    Choose "Transfer" or "Scan QR"
                  </li>
                  <li className="flex items-start">
                    <span className="bg-blue-500 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs mr-2 mt-0.5">3</span>
                    Enter the transfer information above
                  </li>
                  <li className="flex items-start">
                    <span className="bg-blue-500 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs mr-2 mt-0.5">4</span>
                    <strong>Important: Enter the correct transfer content</strong>
                  </li>
                  <li className="flex items-start">
                    <span className="bg-blue-500 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs mr-2 mt-0.5">5</span>
                    Confirm and make the transfer
                  </li>
                  <li className="flex items-start">
                    <span className="bg-blue-500 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs mr-2 mt-0.5">6</span>
                    Click "Confirm Payment" below
                  </li>
                </ol>
              </div>

              {/* Warning */}
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
                <div className="flex items-start">
                  <svg className="w-5 h-5 text-yellow-600 mt-0.5 mr-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.987-.833-2.764 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                  <div>
                    <h4 className="font-semibold text-yellow-800">Important Note</h4>
                    <ul className="text-sm text-yellow-700 mt-1 space-y-1">
                      <li>• Please transfer <strong>the exact amount</strong></li>
                      <li>• <strong>Required</strong> to enter the correct transfer content</li>
                      <li>• Funds will be credited to your wallet within 5-10 minutes</li>
                      <li>• Contact support if you do not receive funds after 30 minutes</li>
                    </ul>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-3">
                <button
                  onClick={handleBack}
                  className="flex-1 bg-gray-500 text-white py-3 rounded-lg hover:bg-gray-600 transition-colors"
                >
                  Back
                </button>
                <button
                  onClick={handleConfirmPayment}
                  disabled={loading}
                  className="flex-1 bg-red-600 text-white py-3 rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
                >
                  {loading ? 'Processing...' : 'Confirm Payment'}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="container mx-auto px-4">
        <div className="max-w-lg mx-auto bg-white rounded-lg shadow-lg overflow-hidden">
          {/* Header */}
          <div className="bg-blue-600 text-white p-6">
            <div className="flex items-center justify-between">
              <h1 className="text-xl font-bold">Add Funds to Wallet</h1>
              <button
                onClick={handleBack}
                className="text-white hover:text-gray-200"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>

          {/* Form */}
          <div className="p-6">
            {/* Amount Input */}
            <div className="mb-6">
              <label className="block text-gray-700 font-semibold mb-2">
                Deposit Amount *
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={amount ? formatUSD(parseInt(amount)) : ''}
                  onChange={handleAmountChange}
                  placeholder="Enter amount"
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-right text-lg font-semibold"
                />
                <span className="absolute right-3 top-3 text-gray-500 font-medium">$</span>
              </div>
              <p className="text-sm text-gray-500 mt-1">
                Minimum: {formatUSD(10)} - Maximum: {formatUSD(10000)}
              </p>
            </div>

            {/* Preset Amounts */}
            <div className="mb-6">
              <label className="block text-gray-700 font-semibold mb-3">
                Quick Select
              </label>
              <div className="grid grid-cols-2 gap-3">
                {presetAmounts.map((presetAmount) => (
                  <button
                    key={presetAmount}
                    onClick={() => handlePresetClick(presetAmount)}
                    className={`p-3 rounded-lg border-2 transition-colors ${
                      parseInt(amount) === presetAmount
                        ? 'border-blue-500 bg-blue-50 text-blue-700'
                        : 'border-gray-200 hover:border-gray-300'
                    }`}
                  >
                    {formatUSD(presetAmount)}
                  </button>
                ))}
              </div>
            </div>

            {/* Description */}
            <div className="mb-6">
              <label className="block text-gray-700 font-semibold mb-2">
                Note (optional)
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Enter note if any..."
                rows={3}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-none"
              />
            </div>

            {/* Generate Payment Info Button */}
            <button
              onClick={generatePaymentInfo}
              disabled={!amount || parseInt(amount) < 10}
              className="w-full bg-blue-600 text-white py-4 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-semibold text-lg"
            >
              Generate Payment Information
            </button>

            {/* Security Note */}
            <div className="mt-6 bg-green-50 border border-green-200 rounded-lg p-4">
              <div className="flex items-start">
                <svg className="w-5 h-5 text-green-600 mt-0.5 mr-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div>
                  <h4 className="font-semibold text-green-800">Security</h4>
                  <p className="text-sm text-green-700 mt-1">
                    Transactions are secured by SSL encryption. Funds will be credited to your wallet immediately after successful confirmation.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AddFunds;
