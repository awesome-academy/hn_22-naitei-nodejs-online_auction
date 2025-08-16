import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { CommonModule } from '@common/common.module';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { ProfileModule } from './profile/profile.module';
import { FollowsModule } from './follows/follows.module';
import { ProductsModule } from './products/products.module';
import { AuctionModule } from './auctions/auction.module';
import { join } from 'path';
import { ChatModule } from './chat/chat.module';
import { WalletModule } from './wallet/wallet.module';
import { OrdersModule } from './orders/orders.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    MailerModule.forRoot({
      transport: {
        host: 'smtp.gmail.com',
        port: 587,
        secure: false, // dùng TLS
        auth: {
          user: process.env.GMAIL_USER,          // your@gmail.com
          pass: process.env.GMAIL_APP_PASSWORD,  // 16‑ký tự có App Password
        },
      },
      defaults: {
        from: `"Bid Market" <${process.env.GMAIL_USER}>`,
      },
      template: {
        dir: join(process.cwd(), 'src', 'templates'),
        adapter: new HandlebarsAdapter(),
        options: {
          strict: true,
        },
      },
    }),
    CommonModule,
    AuthModule,
    UsersModule,
    ProfileModule,
    FollowsModule,
    ProductsModule,
    AuctionModule,
    ChatModule,
    WalletModule,
    OrdersModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
