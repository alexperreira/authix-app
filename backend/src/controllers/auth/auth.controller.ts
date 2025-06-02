import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import prisma from '../../prisma/client';
import {error} from 'console';

const registerSchema = z.object({
    username: z.string().min(3).max(30),
    email: z.string().email(),
    password: z.string().min(8),
});

export const registerUser = async (req: Request, res: Response) => {
    // console.log('Incoming body:', req.body);

    // const { username, email, password } = req.body;

    // console.log('Registering user:', { username, email, password, role: 'user' });

    // Insecure logic: no input validation, no hashing
    try {
        const { username, email, password } = registerSchema.parse(req.body);

        const existing = await prisma.user.findFirst({
            where: { OR: [{ email }, { username }] },
        });

        if (existing) {
            return res.status(409).json({ error: 'user already exists' });
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

        // Auto generate fake token
        // const token = `user-${user.id}`;
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

export const loginUser = async (req: Request, res: Response) => {
    const { username, password } = req.body;

    try {
        const user = await prisma.user.findUnique({
            where: { username },
        });

        if (!user || user.password !== password) {
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

        res.json({ message: 'Login successful', token: `user-${user.id}`, role: user.role });
    } catch (error) {
        console.error('Login error', error);
        // res.status(500).json({ error: 'Login failed', details: (error as any).message });
        res.status(401).json({ error: 'Login failed', details: error });
    }
};

export const getCurrentUser = async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer user-')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const userId = parseInt(authHeader.replace('Bearer user-', ''));

    if (isNaN(userId)) {
        return res.status(401).json({ error: 'Invalid token format' });
    }

    try {
        const user  = await prisma.user.findUnique({ where: { id: userId }});

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
        });
    } catch (error) {
        console.error('Get current user error:', error);
        // res.status(500).json({ error: 'Failed to fetch current user', details: (error as any).message});
        res.status(401).json({ error: 'Failed to fetch current user', details: error });
    }
};

// Attackers abuse refresh logic when no security checks or token invalidation exists.
// Mitigate with:
// -- short lived refresh tokens
// -- token rotation (new one issued each time, old one invalidated)
// -- IP/device fingerprinting
// -- blacklisting on logout
// -- storing in HTTP-only cookies

export const refreshToken = (req: Request, res: Response) => {
    const { token } = req.body;

    if (token !== 'fake-jwt-token') {
        res.status(401).json({ error: 'Invalid refresh token' });
        return;
    }

    res.json({ token: 'fake-jwt-token-refreshed' });
};

export const requestPasswordReset = async (req: Request, res: Response) => {
    const { email } = req.body;

    if (!email) {
        res.status(400).json({ error: 'Email is required' });
        return;
    }

    // Insecure: we generate a fake token and just return it instead of emailing
    const fakeResetToken = 'reset-token-12345';

    console.log(`Password reset requested for ${email}`);

    await prisma.log.create({
        data: {
            event: `Password reset requested for email: ${email}`,
        },
    });

    res.json({ message: 'Password reset token generated', resetToken: fakeResetToken });
};

export const resetPassword = async (req: Request, res: Response) => {
    const { token, newPassword } = req.body;

    if (token !== 'reset-token-12345') {
        res.status(400).json({ error: 'Invalid or expired reset token' });
        return;
    }

    try {
        const user = await prisma.user.findFirst(); // Insecure: resets password for first user

        if (!user) {
            res.status(404).json({ error: 'No user found to reset password' });
            return;
        }

        const updated = await prisma.user.update({
            where: { id: user.id },
            data: { password: newPassword },
        });

        await prisma.log.create({
            data: {
                event: `Password reset for user: ${user.username}`,
            },
        });

        res.json({ message: 'Password reset successful', user: updated });
    } catch (error) {
        console.error('Reset password error:', error);
        // res.status(500).json({ error: 'Failed to reset password', details: (error as any).message });
        res.status(401).json({ error: 'Failed to reset password.', details: error });
    }
};

export const listUsers = async (req: Request, res: Response) => {
    try {
        const users = await prisma.user.findMany();
        res.json({ users });
    } catch (error) {
        console.error('List users error:', error);
        res.status(500).json({ error: 'Failed to fetch users', details: (error as any).message });
    }
};

export const listLogs = async (req: Request, res: Response) => {
    try {
        const logs = await prisma.log.findMany({ orderBy: { createdAt: 'desc'} });
        res.json({ logs });
    } catch (error) {
        console.error('List logs error:', error);
        // res.status(500).json({ error: 'Failed to fetch logs', details: (error as any).message });
        res.status(401).json({ error: 'Failed to fetch logs.', details: error });
    }
};
