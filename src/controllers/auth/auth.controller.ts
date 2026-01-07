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
import { OAuth2Client } from 'google-auth-library';
import { authenticator } from 'otplib';

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}

function getGoogleClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;

  if (!clientId || !clientSecret) {
    throw new Error('Google client id and secret missing');
  }

  return new OAuth2Client({
    clientId,
    clientSecret,
    redirectUri,
  });
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

    const { email, password, twoFactorCode } = result.data;
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

    // two-factor guard: if two-factor is not enabled
    if (user.twoFactorEnabled) {
      if (!twoFactorCode || typeof twoFactorCode !== 'string') {
        return res.status(400).json({
          message: '2FA code is required',
        });
      }

      if (!user?.twoFactorSecret) {
        return res.status(400).json({
          message: '2FA misconfigured for this account',
        });
      }

      // verify the code using otplib
      const isValidCode = authenticator.check(twoFactorCode, user.twoFactorSecret);

      if (!isValidCode) {
        return res.status(400).json({
          message: 'Invalid 2FA code'
        })
      }
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
      message: 'Email is required',
    });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.json({
        message:
          'If an account with this email exists, we will send you a reset link',
      });
    }

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

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
    );

    return res.json({
      message:
        'If an account with this email exists, we will send you a reset link',
    });
  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  const { token, password } = req.body as { token?: string; password?: string };

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
      resetPasswordExpires: { $gt: new Date() }, // expiry must be in the future
    });

    if (!user) {
      return res.status(400).json({
        message: 'Invalid or expired token',
      });
    }

    const newPassword = await hashPassword(password);

    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    user.tokenVersion = user.tokenVersion + 1;

    await user.save();

    return res.json({
      message: 'Password reset successful',
    });
  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
}

export async function googleAuthStartHandler(_req: Request, res: Response) {
  try {
    const client = getGoogleClient();

    const url = client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: ['openid', 'email', 'profile'],
    });

    return res.redirect(url);
  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
}

export async function googleAuthCallbackHandler(req: Request, res: Response) {
  const code = req.query.code as string | undefined;

  if (!code) {
    return res.status(400).json({
      message: 'Missing code in callback',
    });
  }

  try {
    const client = getGoogleClient();

    const { tokens } = await client.getToken(code);

    console.log(tokens, code, 'code');

    if (!tokens.id_token) {
      return res.status(400).json({
        message: 'No google id token is present',
      });
    }

    // verify id token and read the user's info
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID as string,
    });

    const payload = ticket.getPayload();

    const email = payload?.email;
    const emailVerified = payload?.email_verified;

    if (!email || !emailVerified) {
      return res.status(400).json({
        message: 'Google email account is not verified',
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString('hex');

      const passwordHash = await hashPassword(randomPassword);

      user = await User.create({
        email: normalizedEmail,
        password: passwordHash,
        role: 'user',
        isEmailVerified: true,
        twoFactorEnabled: false,
      });
    } else {
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }
    }

    const accessToken = createAccessToken(
      user.id,
      user.role as 'user' | 'admin',
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
      message: 'Google login successful',
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

export async function twoFASetupHandler(req: Request, res: Response) {
  const authReq = req as any;

  const authUser = authReq.user;

  if (!authUser) {
    return res.status(401).json({
      message: 'Not authenticated',
    });
  }

  try {
    const user = await User.findById(authUser.id);

    if (!user) {
      return res.status(404).json({
        message: 'User not found',
      });
    }

    const secret = authenticator.generateSecret();
    const issuer = 'ExpertAuthApp';

    const otpAuthUrl = authenticator.keyuri(user.email, issuer, secret);

    user.twoFactorSecret = secret;
    user.twoFactorEnabled = false;

    await user.save();

    return res.json({
      message: '2FA set up suuccessful',
      otpAuthUrl,
      secret,
    });
  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
}

export async function twoFAVerifyHandler(req: Request, res: Response) {
  const authReq = req as any;

  const authUser = authReq.user;

  if (!authUser) {
    return res.status(401).json({
      message: 'Not authenticated',
    });
  }

  const { code } = req.body as {code?: string};
  if (!code) {
    return res.status(400).json({
      message: '2FA code is required'
    })
  }
  try {
    const user = await User.findById(authUser.id);

    if (!user) {
      return res.status(404).json({
        message: 'User not found',
      });
    }

    if (!user.twoFactorSecret) {
      return res.status(400).json({
        message: 'You do not have 2FA set up',
      })
    }

    const isValid = authenticator.check(code, user.twoFactorSecret);

    if (!isValid) {
      return res.status(404).json({
        message: 'Invalid 2FA code',
      })
    }

    user.twoFactorEnabled = true;
    await user.save();

    return res.json({
      message: '2FA enabled successfully',
      twoFactorEnabled: true
    })


  } catch (error) {
    console.log('Internal server error', error);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
}
