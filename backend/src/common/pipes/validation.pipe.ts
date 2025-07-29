import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';
import { validate, ValidationError } from 'class-validator';
import { plainToInstance } from 'class-transformer';

@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  async transform(value: any, { metatype }: ArgumentMetadata) {
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }
    const object = plainToInstance(metatype, value, {
      enableImplicitConversion: true,
    });
    const errors = await validate(object);

    if (errors.length > 0) {
      const errorMessages = this.formatErrors(errors);
      throw new BadRequestException({
        message: errorMessages,
      });
    }
    return object;
  }

  private toValidate(metatype: Function): boolean {
    const types: Function[] = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }

  private formatErrors(errors: ValidationError[]): string[] {
    const messages: string[] = [];

    errors.forEach((err) => {
      console.log(err);
      const constraints = err.constraints ?? {};
      Object.values(constraints).forEach((message: string) => {
        messages.push(message);
      });
    });
    return messages;
  }
}
