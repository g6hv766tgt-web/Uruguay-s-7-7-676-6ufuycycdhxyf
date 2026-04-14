// api/generate-keys.js
// Called by Vercel cron every day at midnight (0 0 * * *)
// Can also be triggered manually with the correct CRON_SECRET

import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';
import { randomBytes } from 'crypto';

// Cryptographically secure 20-character key using alphanumeric chars
function generateKey(length = 20) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = '';
  // Use rejection sampling for uniform distribution
  const needed = length;
  let generated = 0;
  while (generated < needed) {
    const byte = randomBytes(1)[0];
    // Only use bytes that map cleanly (rejection sampling)
    if (byte < 248) {
      key += chars[byte % chars.length];
      generated++;
    }
  }
  return key;
}

function initFirebase() {
  if (getApps().length === 0) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    initializeApp({ credential: cert(serviceAccount) });
  }
  return getFirestore();
}

export default async function handler(req, res) {
  // Vercel cron sends GET with Authorization: Bearer <CRON_SECRET>
  // Manual trigger can also POST with the same header
  const authHeader = req.headers['authorization'];
  const cronSecret = process.env.CRON_SECRET;

  if (!cronSecret) {
    return res.status(500).json({ error: 'CRON_SECRET not configured' });
  }

  if (authHeader !== `Bearer ${cronSecret}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const db = initFirebase();
    const accessKey = generateKey(20);
    const lockKey = generateKey(20);
    const today = new Date().toISOString().split('T')[0];

    await db.collection('access').doc('keys').set({
      accessKey,
      lockKey,
      isLocked: false,
      date: today,
      updatedAt: new Date().toISOString(),
    });

    console.log(`[generate-keys] Keys generated for ${today}`);
    return res.status(200).json({
      success: true,
      message: 'Keys generated successfully',
      date: today,
    });
  } catch (error) {
    console.error('[generate-keys] Error:', error);
    return res.status(500).json({ error: 'Failed to generate keys' });
  }
}
