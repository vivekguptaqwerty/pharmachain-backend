import { Router } from 'express';
import { adminLogin, getUsers, verifyUser } from '../controllers/adminController';
import { authenticateAdmin } from '../middleware/auth';
import { check } from 'express-validator';
import { validateRequest } from '../middleware/validate';

const router = Router();

router.post(
  '/login',
  [
    check('email').isEmail().withMessage('Invalid email address'),
    check('password').notEmpty().withMessage('Password is required'),
    validateRequest,
  ],
  adminLogin
);
router.get('/users', authenticateAdmin, getUsers);
router.post(
  '/verify-user',
  [
    check('userId').notEmpty().withMessage('User ID is required'),
    check('status').isIn(['approved', 'rejected']).withMessage('Invalid status'),
    validateRequest,
  ],
  authenticateAdmin,
  verifyUser
);

export default router;