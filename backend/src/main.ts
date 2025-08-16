import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { AdminSeederService } from './common/services/admin-seeder.service';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);

  // Global validation pipe
  app.useGlobalPipes(new ValidationPipe({
    transform: true,
    whitelist: true,
    forbidNonWhitelisted: false, 
  }));

  app.setGlobalPrefix('api');
  app.enableCors({
    origin: 'http://localhost:5173',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    credentials: true, 
  });

  // Create admin user on startup
  const adminSeederService = app.get(AdminSeederService);
  await adminSeederService.seedAdminUser();

  await app.listen(process.env.PORT ?? 3000);
}

bootstrap();
