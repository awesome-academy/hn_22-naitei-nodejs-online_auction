import { Global, Module } from '@nestjs/common';
import HttpExceptionFilter from '@common/filters/http-exception.filter';
import AllExceptionsFilter from '@common/filters/all-exception.filter';
import TokenService from '@common/services/token.service';
import { JwtModule } from '@nestjs/jwt';
import JwtAuthGuard from '@common/guards/jwt.guard';
import PrismaService from '@common/services/prisma.service';
import ValidationPipe from '@common/pipes/validation.pipe';
import PasswordService from '@common/services/password.service';
import { RoleGuard } from './guards/role.guard';
import { UploadFileServiceS3 } from './services/file.service';
import { AdminSeederService } from './services/admin-seeder.service';

const service = [TokenService, PrismaService, PasswordService, UploadFileServiceS3, AdminSeederService];

@Global()
@Module({
  imports: [JwtModule],
  providers: [
    ...service,
    {
      provide: 'APP_FILTER',
      useClass: AllExceptionsFilter,
    },
    {
      provide: 'APP_FILTER',
      useClass: HttpExceptionFilter,
    },
    {
      provide: 'APP_GUARD',
      useClass: JwtAuthGuard,
    },
    {
      provide: 'APP_GUARD',
      useClass: RoleGuard,
    },
    {
      provide: 'APP_PIPE',
      useClass: ValidationPipe,
    },
  ],
  exports: [...service],
})
export class CommonModule {}
