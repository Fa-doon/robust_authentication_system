import { Request, Response, Router } from 'express';
import { requireAuth } from '../middlewares/requireAuth';
import { User } from '../models/user.model';
import { requireRole } from '../middlewares/requireRole';

const router = Router();

router.get('/list', requireAuth, requireRole('admin'), async (_req: Request, res: Response) => {
  try {
    const users = await User.find(
      {},
      {
        email: 1,
        role: 1,
        isEmailVerified: 1,
        createdAt: 1,
      }
    ).sort({ createdAt: -1 });

    const result = users.map(u => ({
      id: u.id,
      email: u.email,
      role: u.role,
      isEmailVerified: u.isEmailVerified,
      createdAt: u.createdAt,
    }));

    return res.json({ users: result });
  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
});

export default router;
