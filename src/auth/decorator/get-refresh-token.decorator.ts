import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetRefreshToken = createParamDecorator(
  (_data: undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<any>();
    const authHeader =
      request?.headers?.authorization ?? request?.headers?.['authorization'];
    if (typeof authHeader !== 'string') return undefined;
    const [type, token] = authHeader.split(' ');
    if (type !== 'Bearer') return undefined;
    return token;
  },
);
