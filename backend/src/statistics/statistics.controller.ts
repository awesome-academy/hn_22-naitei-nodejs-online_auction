import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { StatisticsService } from './statistics.service';
import { StatisticsQueryDto } from './dtos/statistics-query.dto';
import { SellerStatisticsResponseDto } from './dtos/seller-statistics-response.dto';
import JwtAuthGuard from '@common/guards/jwt.guard';
import { RoleGuard } from '@common/guards/role.guard';
import { Roles } from '@common/decorators/roles.decorator';
import { CurrentUser } from '@common/decorators/user.decorator';
import { Role } from '@common/enums/role.enum';
import { TokenPayload } from '@common/types/token-payload.interface';

@Controller('statistics')
@UseGuards(JwtAuthGuard, RoleGuard)
export class StatisticsController {
    constructor(private readonly statisticsService: StatisticsService) { }

    @Get('seller')
    @Roles(Role.SELLER)
    async getSellerStatistics(
        @Query() query: StatisticsQueryDto,
        @CurrentUser() user: TokenPayload,
    ): Promise<SellerStatisticsResponseDto> {
        return this.statisticsService.getSellerStatistics(user.id, query);
    }
}
