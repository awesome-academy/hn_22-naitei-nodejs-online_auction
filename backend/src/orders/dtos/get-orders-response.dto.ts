import { OrderResponseDto } from './order-response.dto';

export interface GetOrdersResponseDto {
  orders: OrderResponseDto[];
  pagination: {
    currentPage: number;
    totalPages: number;
    totalItems: number;
    itemsPerPage: number;
    hasNextPage: boolean;
    hasPreviousPage: boolean;
  };
}
