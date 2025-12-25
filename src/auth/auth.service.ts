import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/client';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto) {
    // generate the password hash
    const password = await argon.hash(dto.password);
    // save the new user in the db
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password,
        },
      });
      const tokens = await this.getTokens(user.id, user.email);
      await this.updateRefreshTokenHash(user.id, tokens.refresh_token);

      // remove password before returning
      const { password: _, ...safeUser } = user;

      return {
        user: safeUser,
        ...tokens,
      };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // find the user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // if user does not exist throw exception
    if (!user) throw new ForbiddenException('Credentials incorrect');

    // compare password
    const pwMatches = await argon.verify(user.password, dto.password);
    // if password incorrect throw exception
    if (!pwMatches) throw new ForbiddenException('Credentials incorrect');
    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refresh_token);

    const { password: _, hashedRt, ...safeUser } = user;

    return {
      ...safeUser,
      ...tokens,
    };
  }

  async logout(userId: number) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt: null },
    });
    return { message: 'Logged out' };
  }

  async refreshTokens(userId: number, refreshToken: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.hashedRt) {
      throw new ForbiddenException('Access Denied');
    }

    const rtMatches = await argon.verify(user.hashedRt, refreshToken);
    if (!rtMatches) {
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refresh_token);

    return tokens;
  }

  private async updateRefreshTokenHash(userId: number, refreshToken: string) {
    const hash = await argon.hash(refreshToken);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt: hash },
    });
  }

  private async getTokens(userId: number, email: string) {
    const payload = { sub: userId, email };

    const accessSecret = this.config.get<string>('JWT_SECRET')!;
    const accessExp = this.config.get('JWT_EXPIRES_IN');
    const refreshSecret =
      this.config.get<string>('REFRESH_JWT_SECRET') ?? accessSecret;
    const refreshExp = this.config.get('REFRESH_JWT_EXPIRES_IN');

    const [access_token, refresh_token] = await Promise.all([
      this.jwt.signAsync(payload, {
        expiresIn: accessExp,
        secret: accessSecret,
      }),
      this.jwt.signAsync(payload, {
        expiresIn: refreshExp,
        secret: refreshSecret,
      }),
    ]);

    return { access_token, refresh_token };
  }

  // async signToken(userId: number, email: string): Promise<string> {
  //   const payload = {
  //     sub: userId,
  //     email,
  //   };

  //   const secret = this.config.get('JWT_SECRET');

  //   return this.jwt.signAsync(payload, {
  //     expiresIn: '15m',
  //     secret,
  //   });
  // }
}
