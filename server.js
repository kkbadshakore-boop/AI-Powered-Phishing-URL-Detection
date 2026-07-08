/**
 * PhishGuard — Server
 * Node.js + Express Backend
 */

"use strict";

const express    = require("express");
const cors       = require("cors");
const helmet     = require("helmet");
const rateLimit  = require("express-rate-limit");
const path       = require("path");
const detectRoutes = require("./routes/detectRoutes");

const app  = express();
const PORT = process.env.PORT || 3000;

// ── SECURITY MIDDLEWARE ─────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // allow inline scripts in dev
}));

app.use(cors({
  origin: ["http://localhost:3000", "http://127.0.0.1:5500", "http://localhost:5500"],
  methods: ["GET", "POST", "DELETE"],
  allowedHeaders: ["Content-Type"],
}));

// ── RATE LIMITING ────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                  // 100 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please wait before scanning again." },
});
app.use("/api/", limiter);

// ── BODY PARSING ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

// ── STATIC FILES ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

// ── API ROUTES ────────────────────────────────────────────────────────────────
app.use("/api", detectRoutes);

// ── ROOT ──────────────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// ── ERROR HANDLER ─────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error("[ERROR]", err.message);
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === "production" ? "Internal server error" : err.message
  });
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡  PhishGuard API running on http://localhost:${PORT}`);
  console.log(`📡  POST /api/analyze   — analyze a URL`);
  console.log(`📋  GET  /api/history   — get scan history`);
  console.log(`🗑   DELETE /api/history — clear history\n`);
});

module.exports = app;
