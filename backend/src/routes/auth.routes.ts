import { Router, Request, Response, NextFunction } from 'express';
import { registerUser, loginUser, getCurrentUser, refreshToken, requestPasswordReset, resetPassword, listUsers, listLogs } from '../controllers/auth/auth.controller';

const router = Router();

// Helper function to handle async route handlers in Express 5
const asyncHandler = (fn: any) => (req: Request, res: Response, next: NextFunction) => {
  return Promise.resolve(fn(req, res, next)).catch(next);
};

router.post('/register', asyncHandler(registerUser));
router.post('/login', asyncHandler(loginUser));
router.get('/me', asyncHandler(getCurrentUser));
router.post('/refresh', refreshToken);
router.post('/request-password-reset', asyncHandler(requestPasswordReset));
router.post('/reset-password', asyncHandler(resetPassword));
router.get('/admin/users', asyncHandler(listUsers));
router.get('/admin/logs', asyncHandler(listLogs));

export default router;