export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method Not Allowed' });
    return;
  }

  res.setHeader('Set-Cookie', 'gc_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.status(200).json({ ok: true });
}
