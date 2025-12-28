import jwt from 'jsonwebtoken';

export function createAccessToken(
  userId: string,
  role: 'user' | 'admin',
  tokenVersion: number
) {
  const payload = { sub: userId, role, tokenVersion };

  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: '30m',
  });
}

export function createRefreshToken(userId: string, tokenVersion: number) {
  const payload = { sub: userId, tokenVersion };

  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, { expiresIn: '7d' });
}
