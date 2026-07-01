import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  // GET -> redirect to login page
  if (req.method === 'GET') {
    res.writeHead(302, { Location: '/login.html' });
    res.end();
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method Not Allowed' });
    return;
  }

  const secret = process.env.GC_JWT_SECRET;
  if (!secret) {
    res.status(500).json({ error: 'GC_JWT_SECRET not configured' });
    return;
  }

  const usersRaw = process.env.GC_USERS;
  if (!usersRaw) {
    res.status(500).json({ error: 'GC_USERS not configured' });
    return;
  }

  let users;
  try {
    users = JSON.parse(usersRaw);
  } catch (e) {
    res.status(500).json({ error: 'GC_USERS is not valid JSON' });
    return;
  }

  const { email, password } = req.body || {};
  if (!email || !password) {
    res.status(400).json({ error: 'email e password são obrigatórios' });
    return;
  }

  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) {
    res.status(401).json({ error: 'Credenciais inválidas' });
    return;
  }

  const valid = await bcrypt.compare(password, user.hash);
  if (!valid) {
    res.status(401).json({ error: 'Credenciais inválidas' });
    return;
  }

  const token = jwt.sign({ email: user.email }, secret, { expiresIn: '8h' });

  const isProduction = process.env.VERCEL_ENV === 'production';
  const cookieParts = [
    `gc_token=${token}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    'Max-Age=28800',
  ];
  if (isProduction) cookieParts.push('Secure');

  res.setHeader('Set-Cookie', cookieParts.join('; '));
  res.status(200).json({ ok: true });
}
