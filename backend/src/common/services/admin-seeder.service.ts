import { Injectable, Logger } from '@nestjs/common';
import PrismaService from './prisma.service';
import PasswordService from './password.service';
import { Role } from '@prisma/client';

@Injectable()
export class AdminSeederService {
  private readonly logger = new Logger(AdminSeederService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly passwordService: PasswordService,
  ) {}

  async seedAdminUser(): Promise<void> {
    try {
      const adminEmail = process.env.ADMIN_EMAIL || 'admin@auction.com';
      const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';

      // Check if admin user already exists
      const existingAdmin = await this.prisma.user.findUnique({
        where: { email: adminEmail },
      });

      if (existingAdmin) {
        this.logger.log('Admin user already exists');
        return;
      }

      // Create admin user
      const hashedPassword = await this.passwordService.hashPassword(adminPassword);
      
      const adminUser = await this.prisma.user.create({
        data: {
          email: adminEmail,
          password: hashedPassword,
          role: Role.ADMIN,
          isVerified: true,
        },
      });

      this.logger.log(`Admin user created successfully with email: ${adminEmail}`);
      this.logger.log(`Default admin password: ${adminPassword}`);
    } catch (error) {
      this.logger.error('Failed to create admin user:', error);
    }
  }
}
