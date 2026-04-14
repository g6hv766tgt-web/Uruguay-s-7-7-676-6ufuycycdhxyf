// api/chat.js
// Validates access key, checks lock state, then proxies to Claude Haiku 4.5

import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';
import Anthropic from '@anthropic-ai/sdk';

function initFirebase() {
  if (getApps().length === 0) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    initializeApp({ credential: cert(serviceAccount) });
  }
  return getFirestore();
}

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { key, message } = req.body;

  if (!key || typeof key !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid access key' });
  }

  if (!message || typeof message !== 'string' || message.trim().length === 0) {
    return res.status(400).json({ error: 'Missing or empty message' });
  }

  if (message.length > 8000) {
    return res.status(400).json({ error: 'Message too long (max 8000 characters)' });
  }

  try {
    const db = initFirebase();
    const doc = await db.collection('access').doc('keys').get();

    if (!doc.exists) {
      return res.status(403).json({
        error: 'No access keys configured. Contact the administrator.',
        code: 'NO_KEYS',
      });
    }

    const data = doc.data();

    // Check if system is locked
    if (data.isLocked) {
      return res.status(423).json({
        error: 'System is locked. Access will be restored when new keys are generated at midnight.',
        code: 'LOCKED',
      });
    }

    // Validate the access key (constant-time comparison to prevent timing attacks)
    const keyBuffer = Buffer.from(key.padEnd(20));
    const storedBuffer = Buffer.from(data.accessKey.padEnd(20));
    const keysMatch = keyBuffer.length === storedBuffer.length &&
      require('crypto').timingSafeEqual(keyBuffer, storedBuffer);

    if (!keysMatch || key !== data.accessKey) {
      return res.status(401).json({
        error: 'Invalid access key',
        code: 'INVALID_KEY',
      });
    }

    // Validate key date is today (keys expire at midnight via cron)
    const today = new Date().toISOString().split('T')[0];
    if (data.date && data.date !== today) {
      return res.status(401).json({
        error: 'Access key has expired. New keys are generated at midnight.',
        code: 'EXPIRED_KEY',
      });
    }

    // Send to Claude Haiku 4.5
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1024,
      messages: [
        {
          role: 'user',
          content: message.trim(),
        },
      ],
    });

    const responseText = response.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');

    return res.status(200).json({
      response: responseText,
      model: response.model,
      usage: {
        input_tokens: response.usage.input_tokens,
        output_tokens: response.usage.output_tokens,
      },
    });
  } catch (error) {
    console.error('[chat] Error:', error);

    if (error instanceof Anthropic.APIError) {
      return res.status(502).json({ error: 'Claude API error. Please try again.' });
    }

    return res.status(500).json({ error: 'Internal server error' });
  }
}
