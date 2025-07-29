import { SetMetadata } from '@nestjs/common';

export const jwtConstants = {
  secret: 'Very secret',
};
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
export const AUTH_VALIDATION = {
  PASSWORD: {
    MIN_LENGTH: 6,
    MESSAGE: 'Password must be at least 6 characters long',
  },
};
