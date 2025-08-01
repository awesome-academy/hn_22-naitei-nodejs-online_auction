import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import PrismaService from '../common/services/prisma.service';
import { UserAccountInfoDto } from './dtos/profile.response.dto';
import { SellerAccountInfoDto } from './dtos/seller-profile.response.dto';
import { UpdateProfileDto } from './dtos/update-profile.body.dto';
import {
  ERROR_USER_NOT_FOUND,
  ERROR_FORBIDDEN_ACCESS_ACCOUNT_INFO,
  ERROR_FORBIDDEN_UPDATE_PROFILE,
  ERROR_UPDATE_PROFILE_FAILED,
  ERROR_USER_ALREADY_BANNED,
  ERROR_WARNING_NOT_FOUND,
} from '@common/constants/error.constant';
import { CreateWarningDto } from './dtos/create.warning.dto';
import { UserWarningStatusDto } from './dtos/warning.response.dto';
import { User } from 'generated/prisma';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) { }

  async getUserAccountInfo(
    userId: string,
    currentUser: { id: string; email: string },
  ): Promise<UserAccountInfoDto | SellerAccountInfoDto> {
    const user = await this.prisma.user.findUnique({
      where: { userId },
      include: {
        profile: true,
        addresses: true,
        warnings: true,
      },
    });

    if (!user) {
      throw new NotFoundException(ERROR_USER_NOT_FOUND);
    }

    if (user.isBanned && currentUser.id !== userId) {
      throw new ForbiddenException(ERROR_USER_ALREADY_BANNED);
    }

    if (currentUser.id === userId) {
      return {
        userId: user.userId,
        email: user.email,
        role: user.role,
        isBanned: user.isBanned,
        isVerified: user.isVerified,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        profile: user.profile
          ? [
            {
              fullName: user.profile.fullName || undefined,
              phoneNumber: user.profile.phoneNumber || undefined,
              profileImageUrl: user.profile.profileImageUrl || undefined,
              createdAt: user.profile.createdAt || undefined,
              updatedAt: user.profile.updatedAt || undefined,
            },
          ]
          : [],
        addresses:
          user.addresses?.length > 0
            ? user.addresses.map((address) => ({
              addressId: address.addressId || undefined,
              streetAddress: address.streetAddress || undefined,
              city: address.city || undefined,
              state: address.state || undefined,
              postalCode: address.postalCode || undefined,
              country: address.country || undefined,
              addressType: address.addressType || undefined,
              createdAt: address.createdAt || undefined,
              updatedAt: address.updatedAt || undefined,
            }))
            : [],
      };
    }

    if (user.role === 'SELLER') {
      const [totalProductsSold, followerCount, isFollowedByCurrentUser] =
        await Promise.all([
          this.prisma.product.count({
            where: {
              sellerId: userId,
              status: 'SOLD',
            },
          }),
          this.prisma.follow.count({
            where: {
              sellerId: userId,
            },
          }),
          this.prisma.follow
            .findFirst({
              where: {
                followerId: currentUser.id,
                sellerId: userId,
              },
            })
            .then((follow) => !!follow),
        ]);

      return {
        userId: user.userId,
        role: user.role,
        profile: user.profile
          ? [
            {
              fullName: user.profile.fullName || undefined,
              phoneNumber: user.profile.phoneNumber || undefined,
              profileImageUrl: user.profile.profileImageUrl || undefined,
            },
          ]
          : [],
        addresses:
          user.addresses?.length > 0
            ? user.addresses.map((address) => ({
              streetAddress: address.streetAddress || undefined,
              city: address.city || undefined,
              state: address.state || undefined,
              postalCode: address.postalCode || undefined,
              country: address.country || undefined,
              addressType: address.addressType || undefined,
            }))
            : [],
        stats: {
          totalProductsSold,
          averageRating: undefined, // TODO: implement later when rating system is added
          followerCount,
        },
        isFollowedByCurrentUser,
      };
    }

    throw new ForbiddenException(ERROR_FORBIDDEN_ACCESS_ACCOUNT_INFO);
  }

  async updateProfile(
    userId: string,
    updateProfileDto: UpdateProfileDto,
    currentUser: { id: string; email: string },
  ): Promise<UserAccountInfoDto> {
    if (currentUser.id !== userId) {
      throw new ForbiddenException(ERROR_FORBIDDEN_UPDATE_PROFILE);
    }

    const updatedUser = await this.prisma.$transaction(async (prisma) => {
      const userUpdateData: { email?: string } = {};
      if (updateProfileDto.email) {
        userUpdateData.email = updateProfileDto.email;
      }

      let user;
      if (Object.keys(userUpdateData).length > 0) {
        try {
          user = await prisma.user.update({
            where: { userId },
            data: userUpdateData,
          });
        } catch {
          throw new NotFoundException(ERROR_USER_NOT_FOUND);
        }
      } else {
        user = await prisma.user.findUnique({
          where: { userId },
        });
        if (!user) {
          throw new NotFoundException(ERROR_USER_NOT_FOUND);
        }
      }

      const operations = [];

      if (updateProfileDto.profile) {
        operations.push(
          prisma.profile.upsert({
            where: { userId },
            update: {
              fullName: updateProfileDto.profile.fullName,
              phoneNumber: updateProfileDto.profile.phoneNumber,
              profileImageUrl: updateProfileDto.profile.profileImageUrl,
            },
            create: {
              userId,
              fullName: updateProfileDto.profile.fullName,
              phoneNumber: updateProfileDto.profile.phoneNumber,
              profileImageUrl: updateProfileDto.profile.profileImageUrl,
            },
          }),
        );
      }

      if (updateProfileDto.address) {
        const addressData = updateProfileDto.address;
        if (
          addressData.streetAddress &&
          addressData.city &&
          addressData.country &&
          addressData.addressType
        ) {
          operations.push(
            prisma.address
              .deleteMany({
                where: {
                  userId,
                  addressType: addressData.addressType,
                },
              })
              .then(() =>
                prisma.address.create({
                  data: {
                    userId,
                    streetAddress: addressData.streetAddress!,
                    city: addressData.city!,
                    state: addressData.state,
                    postalCode: addressData.postalCode,
                    country: addressData.country!,
                    addressType: addressData.addressType!,
                  },
                }),
              ),
          );
        }
      }

      if (operations.length > 0) {
        await Promise.all(operations);
      }

      return await prisma.user.findUnique({
        where: { userId },
        select: {
          userId: true,
          email: true,
          role: true,
          isBanned: true,
          isVerified: true,
          createdAt: true,
          updatedAt: true,
          profile: {
            select: {
              fullName: true,
              phoneNumber: true,
              profileImageUrl: true,
              createdAt: true,
              updatedAt: true,
            },
          },
          addresses: {
            select: {
              addressId: true,
              streetAddress: true,
              city: true,
              state: true,
              postalCode: true,
              country: true,
              addressType: true,
              createdAt: true,
              updatedAt: true,
            },
          },
        },
      });
    });

    if (!updatedUser) {
      throw new NotFoundException(ERROR_UPDATE_PROFILE_FAILED);
    }

    return {
      userId: updatedUser.userId,
      email: updatedUser.email,
      role: updatedUser.role,
      isBanned: updatedUser.isBanned,
      isVerified: updatedUser.isVerified,
      createdAt: updatedUser.createdAt,
      updatedAt: updatedUser.updatedAt,
      profile: updatedUser.profile
        ? [
          {
            fullName: updatedUser.profile.fullName || undefined,
            phoneNumber: updatedUser.profile.phoneNumber || undefined,
            profileImageUrl: updatedUser.profile.profileImageUrl || undefined,
            createdAt: updatedUser.profile.createdAt || undefined,
            updatedAt: updatedUser.profile.updatedAt || undefined,
          },
        ]
        : [],
      addresses:
        updatedUser.addresses?.length > 0
          ? updatedUser.addresses.map((addr) => ({
            addressId: addr.addressId || undefined,
            streetAddress: addr.streetAddress || undefined,
            city: addr.city || undefined,
            state: addr.state || undefined,
            postalCode: addr.postalCode || undefined,
            country: addr.country || undefined,
            addressType: addr.addressType || undefined,
            createdAt: addr.createdAt || undefined,
            updatedAt: addr.updatedAt || undefined,
          }))
          : [],
    };
  }

  async createWarning(userId: string,
    createWarningDto: CreateWarningDto,
    adminId: string): Promise<UserWarningStatusDto> {

    const user = await this.prisma.user.findUnique({
      where: { userId: userId }
    });

    if (!user) {
      throw new NotFoundException(ERROR_USER_NOT_FOUND);
    }

    if (user.isBanned) {
      throw new ForbiddenException(ERROR_USER_ALREADY_BANNED);
    }

    const result = await this.prisma.$transaction(async (prisma) => {
      const warning = await prisma.warning.create({
        data: {
          userId: userId,
          adminId: adminId,
          reason: createWarningDto.reason,
          description: createWarningDto.description,
        }
      });

      // Đếm số warnings của user
      const warningCount = await prisma.warning.count({
        where: { userId: userId }
      });

      // Nếu đủ 3 warnings thì ban user
      const shouldBan = warningCount >= 3;

      const updatedUser = await prisma.user.update({
        where: { userId: userId },
        data: {
          warningCount: warningCount,
          isBanned: shouldBan,
        }
      });

      const userWarnings = await prisma.warning.findMany({
        where: { userId: userId },
        orderBy: { createdAt: 'asc' }
      });

      return {
        user: updatedUser,
        warnings: userWarnings,
        newWarning: warning
      };
    });

    return {
      userId: result.user.userId,
      warningCount: result.user.warningCount,
      isBanned: result.user.isBanned,
      warnings: result.warnings.map(w => ({
        warningId: w.warningId,
        userId: w.userId,
        adminId: w.adminId,
        reason: w.reason,
        description: w.description,
        createdAt: w.createdAt
      })),
      message: result.user.isBanned
        ? 'User has been banned due to 3 warnings'
        : `Warning created. User has ${result.user.warningCount}/3 warnings`
    };
  }

  async getUserWarnings(userId: string): Promise<UserWarningStatusDto> {
    const user = await this.prisma.user.findUnique({
      where: { userId },
      include: {
        warnings: {
          orderBy: { createdAt: 'asc' }
        }
      }
    });

    if (!user) {
      throw new NotFoundException(ERROR_USER_NOT_FOUND);
    }

    return {
      userId: user.userId,
      warningCount: user.warningCount,
      isBanned: user.isBanned,
      warnings: user.warnings.map(w => ({
        warningId: w.warningId,
        userId: w.userId,
        adminId: w.adminId,
        reason: w.reason,
        description: w.description,
        createdAt: w.createdAt
      })),
      message: `User has ${user.warningCount} warnings`
    };
  }

  async removeWarning(warningId: string): Promise<UserWarningStatusDto> {
    const warning = await this.prisma.warning.findUnique({
      where: { warningId }
    });

    if (!warning) {
      throw new NotFoundException(ERROR_WARNING_NOT_FOUND);
    }

    const result = await this.prisma.$transaction(async (prisma) => {
      await prisma.warning.delete({
        where: { warningId }
      });

      // Cập nhật warning count và unban
      const newWarningCount = await prisma.warning.count({
        where: { userId: warning.userId }
      });

      const updatedUser = await prisma.user.update({
        where: { userId: warning.userId },
        data: {
          warningCount: newWarningCount,
          isBanned: newWarningCount >= 3
        }
      });

      // Lấy warnings còn lại của user
      const remainingWarnings = await prisma.warning.findMany({
        where: { userId: warning.userId },
        orderBy: { createdAt: 'asc' }
      });

      return {
        user: updatedUser,
        warnings: remainingWarnings
      };
    });

    return {
      userId: result.user.userId,
      warningCount: result.user.warningCount,
      isBanned: result.user.isBanned,
      warnings: result.warnings.map(w => ({
        warningId: w.warningId,
        userId: w.userId,
        adminId: w.adminId,
        reason: w.reason,
        description: w.description ?? undefined,
        createdAt: w.createdAt
      })),
      message: result.user.isBanned
        ? `Warning removed. User still banned (${result.user.warningCount}/3 warnings)`
        : `Warning removed successfully. User unbanned (${result.user.warningCount}/3 warnings)`
    };
  }
}
