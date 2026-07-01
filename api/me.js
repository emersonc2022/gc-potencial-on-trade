import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'Method Not Allowed' });
    return;
  }

  const secret = process.env.GC_JWT_SECRET;
  if (!secret) {
    res.status(500).json({ error: 'GC_JWT_SECRET not configured' });
    return;
  }

  const cookieHeader = req.headers['cookie'] || '';
  const match = cookieHeader.match(/(?:^|;\s*)gc_token=([^;]+)/);
  if (!match) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const token = match[1];
  try {
    const payload = jwt.verify(token, secret);
    res.status(200).json({ email: payload.email });
  } catch (e) {
    res.status(401).json({ error: 'Unauthorized' });
  }
}
