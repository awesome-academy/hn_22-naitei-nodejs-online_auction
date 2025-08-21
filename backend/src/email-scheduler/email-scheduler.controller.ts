import { Controller, Post, UseGuards } from '@nestjs/common';
import { EmailSchedulerService } from './email-scheduler.service';
import JwtAuthGuard from '@common/guards/jwt.guard';
import { RoleGuard } from '@common/guards/role.guard';
import { Roles } from '@common/decorators/roles.decorator';
import { Role } from '@common/enums/role.enum';

@Controller('email-scheduler')
@UseGuards(JwtAuthGuard, RoleGuard)
export class EmailSchedulerController {
    constructor(private readonly emailSchedulerService: EmailSchedulerService) { }

    @Post('test-monthly-reports')
    @Roles(Role.ADMIN)
    async sendTestReports() {
        await this.emailSchedulerService.sendTestReports();
        return { message: 'Test reports sent successfully' };
    }
}
