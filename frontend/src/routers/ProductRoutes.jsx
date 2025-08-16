import { Route, Routes } from "react-router-dom";
import AddMultipleProducts from "@/screens/products/AddMultipleProducts/index.jsx";
import EditProduct from "@/screens/products/EditProduct/index.jsx";

export const ProductRoutes = () => {
  return (
    <Routes>
      <Route path="add" element={<AddMultipleProducts />} />
      <Route path="add-multiple" element={<AddMultipleProducts />} />
      <Route path="edit/:id" element={<EditProduct />} />
    </Routes>
  );
};
