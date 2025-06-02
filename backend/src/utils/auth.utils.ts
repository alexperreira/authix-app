import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const SALT_ROUNDS = 12;

export const hashPassword = (password: string): Promise<string> => {
    return bcrypt.hash(password, SALT_ROUNDS);
};

export const comparePassword = (password: string, hash: string): Promise<boolean> => {
    return bcrypt.compare(password, hash);
};

export const generateToken = (payload: object): string => {
    return jwt.sign(payload, process.env.JWT_SECRET as string, { expiresIn: '1h' });
};

export const verifyToken = (token: string): any => {
    return jwt.verify(token, process.env.JWT_SECRET as string);
};