/**
 * PhishGuard — Detection Controller
 */

"use strict";

const { analyzeUrl: runAnalysis } = require("../services/urlAnalyzer");

// In-memory history (replace with MongoDB model if DB is connected)
let scanHistory = [];
const MAX_HISTORY = 500;

/**
 * POST /api/analyze
 */
exports.analyzeUrl = async (req, res, next) => {
  try {
    const { url } = req.body;
    const result = await runAnalysis(url);

    // Store in history
    const entry = {
      ...result,
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      ip: req.ip,
    };
    scanHistory.unshift(entry);
    if (scanHistory.length > MAX_HISTORY) scanHistory.pop();

    // Return result (strip internal IP field)
    const { ip, ...safeEntry } = entry;
    res.status(200).json(safeEntry);
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/history
 */
exports.getHistory = (req, res) => {
  const { limit = 50, offset = 0, filter } = req.query;

  let results = scanHistory;
  if (filter && filter !== "all") {
    const filterMap = {
      safe: ["Safe", "Low Risk"],
      suspicious: ["Suspicious"],
      malicious: ["Malicious"],
    };
    const statuses = filterMap[filter] || [];
    results = results.filter(r => statuses.includes(r.status));
  }

  const paginated = results.slice(Number(offset), Number(offset) + Number(limit));
  res.json({
    total: results.length,
    offset: Number(offset),
    limit: Number(limit),
    results: paginated.map(({ ip, ...r }) => r), // strip IP
  });
};

/**
 * DELETE /api/history
 */
exports.clearHistory = (req, res) => {
  scanHistory = [];
  res.json({ message: "Scan history cleared.", cleared: true });
};
