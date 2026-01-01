import { Request, Response } from 'express';
import { loginSchema, registerSchema } from './auth.schema';
import { User } from '../../models/user.model';
import { checkPassword, hashPassword } from '../../lib/hash';
import jwt from 'jsonwebtoken';
import { sendEmail } from '../../lib/email';
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from '../../lib/token';
import crypto from 'crypto';

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}

export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: 'Invalid data',
        errors: result.error.flatten(),
      });
    }

    const { name, email, password } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res.status(409).json({
        message:
          'This email is already in use. Please provide another email and try again',
      });
    }

    const passwordHash = await hashPassword(password);

    const createdUser = await User.create({
      name,
      email: normalizedEmail,
      password: passwordHash,
      role: 'user',
      isEmailVerified: false,
      twoFactorEnabled: false,
    });

    // email verification
    const verifyToken = jwt.sign(
      { sub: createdUser.id },
      process.env.JWT_ACCESS_SECRET!,
      { expiresIn: '1d' }
    );

    const verifyURL = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      createdUser.email,
      'Verify your email',
      `<p>Please verify your email by clicking this link:</p>
      
      <p><a href="${verifyURL}">${verifyURL}</a></p>

      `
    );

    return res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: createdUser.id,
        email: createdUser.email,
        role: createdUser.role,
        isEmailVerified: createdUser.isEmailVerified,
      },
    });
  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.query.token as string | undefined;

  if (!token) {
    return res.status(400).json({
      message: 'Missing verification token',
    });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      sub: string;
    };

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    if (user.isEmailVerified) {
      return res.json({ message: 'Email is already verified' });
    }

    user.isEmailVerified = true;
    await user.save();

    return res.json({
      message: 'Email verification successful! You can login',
    });
  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const result = loginSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: 'Invalid data',
        errors: result.error.flatten(),
      });
    }

    const { email, password } = result.data;
    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const ok = await checkPassword(password, user.password);

    if (!ok) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: 'Please verify your email before logging in',
      });
    }

    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === 'production';

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 1000,
    });

    return res.status(200).json({
      message: 'Login successful',
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
}

export async function refreshTokenHandler(req: Request, res: Response) {
  try {
    const token = req.cookies?.refreshToken as string | undefined;

    if (!token) {
      return res.status(401).json({
        message: 'Refresh token missing',
      });
    }

    const payload = verifyRefreshToken(token);
    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(401).json({
        message: 'User not found',
      });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({
        message: 'Invalid refresh token',
      });
    }

    const newAccessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );

    const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === 'production';

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 1000,
    });

    return res.status(200).json({
      message: 'Token refreshed',
      accessToken: newAccessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
}

export async function logoutHandler(req: Request, res: Response) {
  res.clearCookie('refreshToken', { path: '/' });
  return res.status(200).json({
    message: 'Logged out successfully',
  });
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  const { email } = req.body as { email?: string };

  // move to validation file
  if (!email) {
    return res.status(400).json({
       message: 'Email is required'
    })
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.json({
        message: 'If an account with this email exists, we will send you a reset link'
      })
    }

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await user.save();

    const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawToken}`;

    await sendEmail(
      user.email,
      'Reset your password',
      `
      <p>You requested password reset. Click on the below link to reset your password</p>

      <p><a href=${resetUrl}>${resetUrl}</a></p>
      `
    )

    return res.json({
      message: 'If an account with this email exists, we will send you a reset link'
    })
  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {

  const {token, password} = req.body as {token?: string, password?: string};

  if (!token) {
    return res.status(401).json({
      message: 'Refresh token missing',
    });
  }

  if (!password || password.length < 6) {
    return res.status(400).json({
      message: 'Password must be at least 6 characters long',
    });
  }

  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: {$gt: new Date()} // expiry must be in the future
    })

    if (!user){
      return res.status(400).json({
        message: 'Invalid or expired token'
      })
    }

    const newPassword = await hashPassword(password);

    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    user.tokenVersion = user.tokenVersion + 1;

    await user.save();

    return res.json({
      message: 'Password reset successful'
    })

  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }


}
