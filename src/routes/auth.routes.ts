import { Router } from 'express';
import {
  forgotPasswordHandler,
  googleAuthCallbackHandler,
  googleAuthStartHandler,
  loginHandler,
  logoutHandler,
  refreshTokenHandler,
  registerHandler,
  resetPasswordHandler,
  twoFASetupHandler,
  twoFAVerifyHandler,
  verifyEmailHandler,
} from '../controllers/auth/auth.controller';
import { requireAuth } from '../middlewares/requireAuth';

const router = Router();

router.post('/register', registerHandler);
router.post('/login', loginHandler);
router.get('/verify-email', verifyEmailHandler);
router.post('/refresh', refreshTokenHandler);
router.post('/logout', logoutHandler);
router.post('/forgot-password', forgotPasswordHandler);
router.post('/reset-password', resetPasswordHandler);
router.get('/google', googleAuthStartHandler);
router.get('/google/callback', googleAuthCallbackHandler);
router.post('/2fa/setup', requireAuth, twoFASetupHandler);
router.post('/2fa/verify', requireAuth, twoFAVerifyHandler);

export default router;
