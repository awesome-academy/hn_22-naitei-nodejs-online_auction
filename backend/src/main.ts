import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { AdminSeederService } from './common/services/admin-seeder.service';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api');
  app.enableCors({
    origin: 'http://localhost:5173', // cho phép frontend truy cập
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    credentials: true, // nếu bạn dùng cookie hoặc Authorization header
  });

  // Create admin user on startup
  const adminSeederService = app.get(AdminSeederService);
  await adminSeederService.seedAdminUser();

  await app.listen(process.env.PORT ?? 3000);
}

bootstrap();
