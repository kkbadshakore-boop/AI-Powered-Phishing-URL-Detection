/**
 * PhishGuard — Detection Routes
 */

"use strict";

const express    = require("express");
const router     = express.Router();
const controller = require("../controllers/detectController");
const { validateUrl } = require("../services/urlAnalyzer");

// Input validation middleware
function urlValidator(req, res, next) {
  const { url } = req.body;
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "URL is required and must be a string." });
  }
  const trimmed = url.trim();
  if (trimmed.length === 0) {
    return res.status(400).json({ error: "URL cannot be empty." });
  }
  if (trimmed.length > 2048) {
    return res.status(400).json({ error: "URL exceeds maximum length of 2048 characters." });
  }
  if (!validateUrl(trimmed)) {
    return res.status(400).json({ error: "Invalid URL format. Please include a valid domain." });
  }
  req.body.url = trimmed;
  next();
}

// POST /api/analyze
router.post("/analyze", urlValidator, controller.analyzeUrl);

// GET /api/history
router.get("/history", controller.getHistory);

// DELETE /api/history
router.delete("/history", controller.clearHistory);

module.exports = router;
