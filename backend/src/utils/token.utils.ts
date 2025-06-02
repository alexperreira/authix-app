import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { addDays } from 'date-fns';
import prisma from '../prisma/client';

const ACCESS_TOKEN_EXPIRY = '15m'; // short-lived access token
const REFRESH_TOKEN_EXPIRY_DAYS = 7;

export const generateAccessToken = (payload: object): string => {
    return jwt.sign(payload, process.env.JWT_SECRET!, { expiresIn: ACCESS_TOKEN_EXPIRY });
};

export const generateRefreshToken = async (userId: number): Promise<string> => {
    const token = crypto.randomBytes(40).toString('hex');
    const expiresAt = addDays(new Date(), REFRESH_TOKEN_EXPIRY_DAYS);

    await prisma.refreshToken.create({
        data: {
            token,
            userId,
            expiresAt,
        },
    });

    return token;
};

export const validateRefreshToken = async (token: string) => {
    const record = await prisma.refreshToken.findUnique({
        where: { token },
        include: { user: true },
    });

    if (!record || record.expiresAt < new Date()) {
        return null;
    }

    return record.user;
};

export const rotateRefreshToken = async (oldToken: string, userId: number): Promise<string> => {
    await prisma.refreshToken.delete({ where: {token: oldToken } });

    return await generateRefreshToken(userId);
}