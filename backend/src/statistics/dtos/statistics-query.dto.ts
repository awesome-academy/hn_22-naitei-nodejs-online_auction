import { IsOptional, IsNumber, Min, Max } from 'class-validator';
import { Transform } from 'class-transformer';

export class StatisticsQueryDto {
    @IsOptional()
    @Transform(({ value }) => {
        if (value === '' || value === null || value === undefined) return undefined;
        const parsed = parseInt(value);
        return isNaN(parsed) ? undefined : parsed;
    })
    @IsNumber()
    @Min(2020)
    @Max(2030)
    year?: number;

    @IsOptional()
    @Transform(({ value }) => {
        if (value === '' || value === null || value === undefined) return undefined;
        const parsed = parseInt(value);
        return isNaN(parsed) ? undefined : parsed;
    })
    @IsNumber()
    @Min(1)
    @Max(12)
    month?: number;

    @IsOptional()
    @Transform(({ value }) => {
        if (value === '' || value === null || value === undefined) return 10;
        const parsed = parseInt(value);
        return isNaN(parsed) ? 10 : parsed;
    })
    @IsNumber()
    @Min(1)
    @Max(50)
    topProductsLimit?: number = 10;
}
