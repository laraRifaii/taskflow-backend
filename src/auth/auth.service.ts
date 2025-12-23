import {
    ForbiddenException,
    Injectable,
  } from '@nestjs/common';
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
        const access_token = await this.signToken(
          user.id,
          user.email,
        );
    
        // remove password before returning
        const { password: _, ...safeUser } = user;
    
        return {
          user: safeUser,
          access_token,
        };

      } catch (error) {
        if (
          error instanceof
          PrismaClientKnownRequestError
        ) {
          if (error.code === 'P2002') {
            throw new ForbiddenException(
              'Credentials taken',
            );
          }
        }
        throw error;
      }
    }
  
    async signin(dto: AuthDto) {
      // find the user by email
      const user =
        await this.prisma.user.findUnique({
          where: {
            email: dto.email,
          },
        });
      // if user does not exist throw exception
      if (!user)
        throw new ForbiddenException(
          'Credentials incorrect',
        );
  
      // compare password
      const pwMatches = await argon.verify(
        user.password,
        dto.password,
      );
      // if password incorrect throw exception
      if (!pwMatches)
        throw new ForbiddenException(
          'Credentials incorrect',
        );
        const access_token = await this.signToken(
          user.id,
          user.email,
        );
      
        const { password: _, ...safeUser } = user;
      
        return {
          ...safeUser,
          access_token,
        };
    }
  


    async signToken(
      userId: number,
      email: string,
    ): Promise<string> {
      const payload = {
        sub: userId,
        email,
      };
    
      const secret = this.config.get('JWT_SECRET');
    
      return this.jwt.signAsync(payload, {
        expiresIn: '15m',
        secret,
      });
    }
    
  }