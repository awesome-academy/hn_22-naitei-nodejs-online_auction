import { Body, Controller, Post } from '@nestjs/common';
import { Public } from './auth.constants';
import { RegisterDTO } from './dtos/register.dto';
import { AuthService } from './auth.service';

@Controller('users')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('register')
  async register(@Body() registerDTO: RegisterDTO) {
    return this.authService.register(registerDTO);
  }
}
