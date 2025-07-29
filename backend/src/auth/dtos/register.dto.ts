import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';
import { AUTH_VALIDATION } from '../auth.constants';

export class RegisterDTO {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(AUTH_VALIDATION.PASSWORD.MIN_LENGTH, {
    message: AUTH_VALIDATION.PASSWORD.MESSAGE,
  })
  password: string;
}
