/**
 * Vercel Serverless Function: Tracking Status & Read Receipts
 * Endpoint: /api/status
 * 
 * Queries real-time open and click analytics for single or batch tracking IDs.
 */

'use strict';

const storage = require('./lib/storage');

module.exports = async function handler(req, res) {
  // CORS & Cache Control headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.setHeader('Content-Type', 'application/json');

  // Handle CORS pre-flight
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'GET') {
    res.status(405).json({
      success: false,
      error: 'Method Not Allowed. Use GET.'
    });
    return;
  }

  // Extract query IDs
  const query = req.query || {};
  let targetIds = [];

  if (query.ids) {
    targetIds = String(query.ids).split(',').map(s => s.trim()).filter(Boolean);
  } else if (query.id) {
    targetIds = [String(query.id).trim()].filter(Boolean);
  }

  if (targetIds.length === 0) {
    res.status(400).json({
      success: false,
      error: 'Missing required query parameter: "id" or "ids"'
    });
    return;
  }

  // Limit batch size to 50 for safety
  const sanitizedIds = targetIds.slice(0, 50);

  try {
    const data = await storage.getMultipleRecords(sanitizedIds);
    res.status(200).json({
      success: true,
      data
    });
  } catch (error) {
    console.error('[MailTracker Status] Error querying status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve tracking status'
    });
  }
};
