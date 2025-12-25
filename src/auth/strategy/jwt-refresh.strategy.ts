import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import * as argon from 'argon2';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export default class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(
    config: ConfigService,
    private prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey:
        config.get<string>('REFRESH_JWT_SECRET') ??
        config.get<string>('JWT_SECRET')!,
      passReqToCallback: true,
    });
  }

  async validate(req: any, payload: { sub: number; email: string }) {
    const refreshToken =
      typeof req?.headers?.authorization === 'string'
        ? req.headers.authorization.replace('Bearer ', '')
        : typeof req?.headers?.['authorization'] === 'string'
          ? req.headers['authorization'].replace('Bearer ', '')
          : undefined;

    if (!refreshToken) {
      throw new ForbiddenException('Access Denied');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user || !user.hashedRt) {
      throw new ForbiddenException('Access Denied');
    }

    const rtMatches = await argon.verify(user.hashedRt, refreshToken);
    if (!rtMatches) {
      throw new ForbiddenException('Access Denied');
    }

    delete (user as any).password;
    delete (user as any).hashedRt;
    return user;
  }
}
