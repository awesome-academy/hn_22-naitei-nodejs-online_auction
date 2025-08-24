export const SHIPPING_STATUS = {
  PENDING: 'PENDING',
  SHIPPED: 'SHIPPED',
  IN_TRANSIT: 'IN_TRANSIT',
  DELIVERED: 'DELIVERED',
};

export const SHIPPING_STATUS_LABELS = {
  [SHIPPING_STATUS.PENDING]: 'Pending',
  [SHIPPING_STATUS.SHIPPED]: 'Shipped',
  [SHIPPING_STATUS.IN_TRANSIT]: 'In Transit',
  [SHIPPING_STATUS.DELIVERED]: 'Delivered',
};

export const SHIPPING_STATUS_COLORS = {
  [SHIPPING_STATUS.PENDING]: {
    bg: 'bg-yellow-100',
    text: 'text-yellow-800',
    border: 'border-yellow-300',
    icon: 'text-yellow-600'
  },
  [SHIPPING_STATUS.SHIPPED]: {
    bg: 'bg-blue-100',
    text: 'text-blue-800',
    border: 'border-blue-300',
    icon: 'text-blue-600'
  },
  [SHIPPING_STATUS.IN_TRANSIT]: {
    bg: 'bg-purple-100',
    text: 'text-purple-800',
    border: 'border-purple-300',
    icon: 'text-purple-600'
  },
  [SHIPPING_STATUS.DELIVERED]: {
    bg: 'bg-green-100',
    text: 'text-green-800',
    border: 'border-green-300',
    icon: 'text-green-600'
  },
};

export const SHIPPING_SORT_OPTIONS = [
  { value: 'createdAt', label: 'Created Date' },
  { value: 'updatedAt', label: 'Updated Date' },
  { value: 'shippedAt', label: 'Shipped Date' },
  { value: 'estimatedDelivery', label: 'Estimated Delivery' },
  { value: 'actualDelivery', label: 'Actual Delivery' },
];
