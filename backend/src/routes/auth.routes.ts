import { Router, Request, Response, NextFunction, RequestHandler } from 'express';
import asyncHandler from 'express-async-handler'
import { wrapMiddleware } from '../utils/wrapMiddleware';
import { requireAdmin, requireAuth } from '../middleware/auth.middleware';
import { registerUser, loginUser, getCurrentUser, refreshToken, requestPasswordReset, resetPassword, listUsers, listLogs } from '../controllers/auth/auth.controller';

const router = Router();

// Public routes
router.post('/register', asyncHandler(registerUser));
router.post('/login', asyncHandler(loginUser));
router.post('/refresh', refreshToken);
router.post('/request-password-reset', asyncHandler(requestPasswordReset));
router.post('/reset-password', asyncHandler(resetPassword));

// Authenticated user route
router.get('/me', wrapMiddleware(requireAuth), asyncHandler(getCurrentUser));

// Admin-only routes
router.get('/admin/users', wrapMiddleware(requireAuth), wrapMiddleware(requireAdmin), asyncHandler(listUsers));
router.get('/admin/logs', wrapMiddleware(requireAuth), wrapMiddleware(requireAdmin), asyncHandler(listLogs));

export default router;