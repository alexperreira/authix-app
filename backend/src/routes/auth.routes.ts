import { Router, Request, Response, NextFunction, RequestHandler } from 'express';
import asyncHandler from 'express-async-handler'
import { wrapMiddleware } from '../utils/wrapMiddleware';
import { requireAdmin, requireAuth } from '../middleware/auth.middleware';
import { registerUser, loginUser, getCurrentUser, refreshToken, requestPasswordReset, resetPassword, listUsers, listLogs, logoutUser, logoutAllSessions } from '../controllers/auth/auth.controller';
import rateLimit from 'express-rate-limit';

const router = Router();

const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 5,
    message: 'Too many login attempts, please try again later.',
});

// Public routes
router.post('/register', asyncHandler(registerUser));
router.post('/login', loginLimiter, asyncHandler(loginUser));
router.post('/refresh', asyncHandler(refreshToken));
router.post('/request-password-reset', asyncHandler(requestPasswordReset));
router.post('/reset-password', asyncHandler(resetPassword));

// Authenticated user route
router.get('/me', wrapMiddleware(requireAuth), asyncHandler(getCurrentUser));
router.get('/logout', asyncHandler(logoutUser));
router.post('/logout-all', wrapMiddleware(requireAuth), asyncHandler(logoutAllSessions));


// Admin-only routes
router.get('/admin/users', wrapMiddleware(requireAuth), wrapMiddleware(requireAdmin), asyncHandler(listUsers));
router.get('/admin/logs', wrapMiddleware(requireAuth), wrapMiddleware(requireAdmin), asyncHandler(listLogs));

export default router;