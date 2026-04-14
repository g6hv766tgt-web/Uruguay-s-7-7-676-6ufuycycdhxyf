// api/lock.js
// Accepts the lock key and immediately disables all API access
// Access is restored only when new keys are generated at midnight

import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';
import { timingSafeEqual } from 'crypto';

function initFirebase() {
  if (getApps().length === 0) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    initializeApp({ credential: cert(serviceAccount) });
  }
  return getFirestore();
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { lockKey } = req.body;

  if (!lockKey || typeof lockKey !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid lock key' });
  }

  try {
    const db = initFirebase();
    const doc = await db.collection('access').doc('keys').get();

    if (!doc.exists) {
      return res.status(403).json({ error: 'No access keys configured' });
    }

    const data = doc.data();

    // Already locked — acknowledge gracefully
    if (data.isLocked) {
      return res.status(200).json({
        message: 'System is already locked.',
        code: 'ALREADY_LOCKED',
      });
    }

    // Validate lock key with timing-safe comparison
    const inputBuffer = Buffer.from(lockKey.padEnd(20));
    const storedBuffer = Buffer.from(data.lockKey.padEnd(20));
    const keysMatch =
      inputBuffer.length === storedBuffer.length &&
      timingSafeEqual(inputBuffer, storedBuffer) &&
      lockKey === data.lockKey;

    if (!keysMatch) {
      return res.status(401).json({ error: 'Invalid lock key', code: 'INVALID_KEY' });
    }

    // Engage the lock
    await db.collection('access').doc('keys').update({
      isLocked: true,
      lockedAt: new Date().toISOString(),
    });

    console.log('[lock] System locked at', new Date().toISOString());
    return res.status(200).json({
      success: true,
      message: 'System locked. All access is disabled until midnight.',
    });
  } catch (error) {
    console.error('[lock] Error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
