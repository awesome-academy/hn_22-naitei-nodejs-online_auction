import { Module } from '@nestjs/common';
import { EmailSchedulerService } from './email-scheduler.service';
import { EmailSchedulerController } from './email-scheduler.controller';
import { CommonModule } from '@common/common.module';

@Module({
    imports: [CommonModule],
    controllers: [EmailSchedulerController],
    providers: [EmailSchedulerService],
    exports: [EmailSchedulerService],
})
export class EmailSchedulerModule { }
