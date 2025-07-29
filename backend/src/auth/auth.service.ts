import { Injectable, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'prisma/prisma.service';
import { RegisterDTO } from './dtos/register.dto';
import * as bcrypt from 'bcrypt';
import { User, Role } from '.prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async register(data: RegisterDTO) {
    const emailExists = await this.prisma.user.findUnique({
      where: { email: data.email },
    });
    if (emailExists) {
      throw new ConflictException('Email đã tồn tại');
    }

    const hashedPassword = await bcrypt.hash(data.password, 10);

    const user = await this.prisma.user.create({
      data: {
        ...data,
        password: hashedPassword,
        role: Role.BIDDER, // Set default role to BIDDER
      },
    });

    return this.buildUserResponse(user);
  }

  private buildUserResponse(user: User) {
    const payload = {
      id: user.userId,
      email: user.email,
    };

    return {
      user: {
        id: user.userId,
        email: user.email,
        token: this.jwtService.sign(payload),
      },
    };
  }
}
