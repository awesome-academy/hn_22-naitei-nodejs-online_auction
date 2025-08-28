import { Title } from "@/components/ui/index.js";
import { useNavigate } from "react-router-dom";

export default function WinnerPopup({isOpen, onClose, price}) {
  const navigate = useNavigate();

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white p-6 rounded-lg shadow-lg max-w-sm w-full">
        <Title level={3} className="mb-3 text-green-700">
          🎉 Congratulations!
        </Title>
        <p className="mb-4">
          You won this auction with bid ${price}.
        </p>
        <div className="flex justify-end gap-3">
          <button
            className="px-4 py-2 rounded bg-red-500 text-white hover:bg-red-700"
            onClick={onClose}
          >
            Close
          </button>
          <button
            className="px-4 py-2 rounded bg-emerald-500 text-white hover:bg-emerald-700"
            onClick={() => navigate(`/profile?tab=Order`)}
          >
            Proceed to Order
          </button>
        </div>
      </div>
    </div>
  );
}
