import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { addMinutes } from 'date-fns';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import prisma from '../../prisma/client';
import { comparePassword, generateToken } from '../../utils/auth.utils';
import { validateRefreshToken, rotateRefreshToken, generateAccessToken, generateRefreshToken } from '../../utils/token.utils';

const registerSchema = z.object({
    username: z.string().min(3).max(30),
    email: z.string().email(),
    password: z.string().min(8),
});

export const registerUser = async (req: Request, res: Response): Promise<void> => {
    try {
        const { username, email, password } = registerSchema.parse(req.body);

        const existing = await prisma.user.findFirst({
            where: { OR: [{ email }, { username }] },
        });

        if (existing) {
            res.status(409).json({ error: 'user already exists' });
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const user = await prisma.user.create({
            data: {
                username,
                email,
                password: hashedPassword,
                role: 'user'
            },
        });

        await prisma.log.create({
            data: {
                event: `User registered: ${username}`,
            },
        });

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET!, {expiresIn: '1h' });

        res.status(201).json({
            message: 'User created',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Prisma error:', error);
        // res.status(400).json({ error: 'Unable to create user', details: (error as any).message });
        res.status(400).json({ error: 'Unable to create user', details: error });
    }
};

export const loginUser = async (req: Request, res: Response): Promise<void> => {
    const { username, password } = req.body;

    try {
        const user = await prisma.user.findUnique({
            where: { username },
        });

        if (!user || !(await comparePassword(password, user.password))) {
            await prisma.log.create({
                data: {
                    event: `Failed login attempt for: ${username}`,
                },
            });

            res.status(401).json({ error: 'Invalid username or password' });
            return;
        }

        await prisma.log.create({
            data: {
                event: `Successful login for: ${username}`,
            },
        });

        const accessToken = generateAccessToken({ id: user.id, role: user.role });
        const refreshToken = await generateRefreshToken(user.id);

        res.json({
            message: 'Login successful',
            accessToken,
            refreshToken,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
            },
        });
    } catch (error) {
        console.error('Login error', error);
        res.status(500).json({ error: 'Login failed' });
    }
};

export const getCurrentUser = async (req: Request, res: Response): Promise<void> => {
    const authHeader = req.headers.authorization;

    const userPayload = (req as any).user;

    if (!userPayload || !userPayload.id) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }

    try {
        const user = await prisma.user.findUnique({
            where: { id: userPayload.id },
        });

        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
        });
    } catch (error) {
        console.error('Get current user error:', error);
        res.status(500).json({ error: 'Failed to fetch user.' });
    }
};

// Attackers abuse refresh logic when no security checks or token invalidation exists.
// Mitigate with:
// -- short lived refresh tokens
// -- token rotation (new one issued each time, old one invalidated)
// -- IP/device fingerprinting
// -- blacklisting on logout
// -- storing in HTTP-only cookies

export const refreshToken = async (req: Request, res: Response): Promise<void> => {
    const { token } = req.body;

    if (!token) {
        res.status(400).json({ error: 'Refresh token is required.' });
        return;
    }

    const user = await validateRefreshToken(token);

    if (!user) {
        res.status(401).json({ error: 'Invalid or expired refresh token.' });
        return;
    }

    const newAccessToken = generateAccessToken({ id: user.id, role: user.role });
    const newRefreshToken = await rotateRefreshToken(token, user.id);

    res.json({
        accesstoken: newAccessToken,
        refreshToken: newRefreshToken,
    });
};



export const requestPasswordReset = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;

    if (!email) {
        res.status(400).json({ error: 'Email is required' });
        return;
    }

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        res.status(404).json({ error: 'No user with that email' });
        return;
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expires = addMinutes(new Date(), 15);

    await prisma.user.update({
        where: { id: user.id },
        data: {
            resetToken: token,
            resetTokenExpires: expires,
        },
    });

    await prisma.log.create({
        data: {
            event: `Password reset requested for email: ${email}.`,
        },
    });

    res.json({
        message: 'Password reset link generated',
        resetToken: token,
    });
};

export const resetPassword = async (req: Request, res: Response): Promise<void> => {
   try {
        const { token, newPassword } = req.body;

        const user = await prisma.user.findFirst({
            where: {
                resetToken: token,
                resetTokenExpires: { gt: new Date() },
            },
    });

    if (!user) {
        res.status(400).json({ error: 'Invalid or expired reset token.' });
        return;
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await prisma.user.update({
        where: { id: user.id },
        data: {
            password: hashedPassword,
            resetToken: null,
            resetTokenExpires: null,
        },
    });

    await prisma.log.create({
        data: {
            event: `Password reset for user: ${user.username}`,
        },
    });

    res.json({ message: 'Password reset successful.' });
   } catch (error) {
        console.error('Reset password error: ', error);
        res.status(500).json({ error: 'Failed to reset password.' });
   };
};

export const listUsers = async (req: Request, res: Response): Promise<void> => {
    try {
        const users = await prisma.user.findMany();
        res.json({ users });
    } catch (error) {
        console.error('List users error:', error);
        res.status(500).json({ error: 'Failed to fetch users', details: (error as any).message });
    }
};

export const listLogs = async (req: Request, res: Response): Promise<void> => {
    try {
        const logs = await prisma.log.findMany({ orderBy: { createdAt: 'desc'} });
        res.json({ logs });
    } catch (error) {
        console.error('List logs error:', error);
        // res.status(500).json({ error: 'Failed to fetch logs', details: (error as any).message });
        res.status(401).json({ error: 'Failed to fetch logs.', details: error });
    }
};

export const logoutUser = async (req: Request, res: Response): Promise<void> => {
    const { token } = req.body;

    if (!token) {
        res.status(400).json({ error: 'Refresh token is required for logout.' });
        return;
    }

    try {
        await prisma.refreshToken.delete({
            where: { token },
        });

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(400).json({ error: 'Token not found or already invalidated' });
    }

}