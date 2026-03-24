const cors = require('cors');
/**
 * eFootball Store — Secure Backend
 * ─────────────────────────────────────────────────────────────
 * Purpose  : Proxy Telegram Bot API calls so the bot token
 *            NEVER travels through the browser.
 * Scale    : ~30 sellers, many customers. Minimal by design.
 * Stack    : Node.js 18+ · Express · dotenv
 * Security : Token lives only in .env on the server.
 *            Clients send event data; server appends the token.
 * ─────────────────────────────────────────────────────────────
 */

"use strict";
const admin = require("firebase-admin");
require("dotenv").config();

const express = require("express");
const https   = require("https");

const app  = express();
const databaseURL = "https://efootball-51715-default-rtdb.firebaseio.com/";
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)),
    databaseURL: "https://efootball-51715-default-rtdb.firebaseio.com/"
  });
}
const db = admin.database();

app.use(cors({
  origin: "https://mohamedreda-ai.github.io",
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));
const PORT = process.env.PORT || 3001;

// ─────────────────────────────────────────────────────────────
//  REQUIRED ENVIRONMENT VARIABLES
//  Copy .env.example → .env and fill in values before deploying.
// ─────────────────────────────────────────────────────────────
const TG_BOT_TOKEN  = process.env.TG_BOT_TOKEN  || "";
const TG_CHAT_ID    = process.env.TG_CHAT_ID    || "";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";

// Fail fast if the token is missing — do not silently run with no notifications.
if (!TG_BOT_TOKEN || !TG_CHAT_ID) {
  console.warn(
    "[WARN] TG_BOT_TOKEN or TG_CHAT_ID not set in .env — " +
    "Telegram notifications will be disabled but server will still run."
  );
}

// ─────────────────────────────────────────────────────────────
//  MIDDLEWARE
// ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: "32kb" })); // reject oversized bodies

// CORS — restrict to the domain serving the frontend in production.
// ALLOWED_ORIGIN="https://yourdomain.com" in .env.
// For local dev, set ALLOWED_ORIGIN="*" or omit it.
app.use(function (req, res, next) {
  res.setHeader("Access-Control-Allow-Origin",  ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ─────────────────────────────────────────────────────────────
//  INPUT VALIDATION HELPERS
// ─────────────────────────────────────────────────────────────

/**
 * Strips null bytes and invisible Unicode spoofing chars.
 * Returns a plain string capped at maxLen characters.
 */
function sanitize(val, maxLen) {
  if (val === null || val === undefined) return "";
  return String(val)
    .replace(/\x00/g, "")
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g, "")
    .slice(0, maxLen || 500);
}

/** Escape HTML-special chars for Telegram HTML parse_mode messages. */
function esc(str) {
  if (!str && str !== 0) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** True if value is a non-empty string after trimming. */
function notEmpty(v) {
  return typeof v === "string" && v.trim().length > 0;
}

// ─────────────────────────────────────────────────────────────
//  RATE LIMITER  (in-memory, per-IP, simple)
//  Limits: 30 notification calls per IP per minute.
//  Enough for ~30 sellers × legitimate activity.
//  Resets automatically every 60 s.
// ─────────────────────────────────────────────────────────────
const _rlWindow = 60_000;   // 1 minute
const _rlMax    = 30;       // requests per window per IP
const _rlMap    = new Map();

function rateLimitMiddleware(req, res, next) {
  const ip  = req.ip || "unknown";
  const now = Date.now();
  let   entry = _rlMap.get(ip);

  if (!entry || now - entry.start > _rlWindow) {
    entry = { start: now, count: 0 };
    _rlMap.set(ip, entry);
  }

  entry.count++;
  if (entry.count > _rlMax) {
    return res.status(429).json({ ok: false, error: "too_many_requests" });
  }
  next();
}

// Prune old IPs every 5 minutes to prevent unbounded Map growth.
setInterval(function () {
  const cutoff = Date.now() - _rlWindow;
  for (const [ip, e] of _rlMap) {
    if (e.start < cutoff) _rlMap.delete(ip);
  }
}, 5 * 60_000);

// ─────────────────────────────────────────────────────────────
//  TELEGRAM SEND  (server-side — token never leaves this file)
// ─────────────────────────────────────────────────────────────
function sendTelegram(text) {
  return new Promise(function (resolve) {
    if (!TG_BOT_TOKEN || !TG_CHAT_ID) {
      console.warn("[TG] Token/ChatId not configured — skipping send");
      return resolve({ ok: false, skipped: true });
    }

    // Truncate at Telegram's 4096 UTF-16 limit
    const safeText = text.length > 4000 ? text.slice(0, 4000) + "…" : text;
    const body     = JSON.stringify({
      chat_id:    TG_CHAT_ID,
      text:       safeText,
      parse_mode: "HTML",
    });

    const options = {
      hostname: "api.telegram.org",
      path:     `/bot${TG_BOT_TOKEN}/sendMessage`,
      method:   "POST",
      headers: {
        "Content-Type":   "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const req = https.request(options, function (res) {
      let raw = "";
      res.on("data", (chunk) => { raw += chunk; });
      res.on("end", function () {
        try {
          const parsed = JSON.parse(raw);
          if (!parsed.ok) console.error("[TG] API error:", parsed.description);
          resolve({ ok: !!parsed.ok });
        } catch {
          resolve({ ok: false });
        }
      });
    });

    req.on("error", function (e) {
      console.error("[TG] Network error:", e.message);
      resolve({ ok: false });
    });

    // 10-second timeout
    req.setTimeout(10_000, function () {
      req.destroy();
      resolve({ ok: false, error: "timeout" });
    });

    req.write(body);
    req.end();
  });
}

// ─────────────────────────────────────────────────────────────
//  MESSAGE BUILDERS  (one per event type)
//  These mirror the messages previously built in TelegramAPI.js
//  but now run on the server with server-side escaping.
// ─────────────────────────────────────────────────────────────
const messageBuilders = {

  whatsapp_click: function (p) {
    return [
      "🟢 <b>مشتري جديد يهتم بحساب!</b>",
      "",
      "🏪 الستور: <b>" + esc(p.storeName) + "</b>",
      "💰 السعر: <b>" + esc(p.price) + " ج</b>",
      p.players ? "⭐ اللاعبون: " + esc(p.players) : null,
      "🕐 " + new Date().toLocaleString("ar-EG"),
    ].filter(Boolean).join("\n");
  },

  waitlist: function (p) {
    return [
      "📋 <b>طلب انتظار جديد!</b>",
      "",
      "🏪 " + esc(p.storeName),
      "👤 الاسم: " + esc(p.name || "مجهول"),
      "📱 واتساب: " + esc(p.whatsapp),
      p.note ? "📝 ملاحظة: " + esc(p.note) : null,
      "🕐 " + new Date().toLocaleString("ar-EG"),
    ].filter(Boolean).join("\n");
  },

  sale: function (p) {
    return [
      "💰 <b>تم بيع حساب!</b>",
      "",
      "🏪 " + esc(p.storeName),
      "💵 السعر: <b>" + esc(p.price) + " ج</b>",
      "📈 مكسبك: <b>" + esc(p.profit) + " ج</b>",
      p.players ? "⭐ " + esc(p.players) : null,
      "🕐 " + new Date().toLocaleString("ar-EG"),
    ].filter(Boolean).join("\n");
  },

  account_request: function (p) {
    const lines = ["🎯 <b>طلب حساب جديد!</b>", ""];
    lines.push("👤 الاسم: " + esc(p.name || "مجهول"));
    lines.push("📱 واتساب: " + esc(p.whatsapp));
    if (p.players)   lines.push("⭐ اللاعبون: " + esc(p.players));
    if (p.minPrice > 0 || p.maxPrice > 0) {
      const ps = p.minPrice > 0 ? p.minPrice + " ج" : "أي سعر";
      lines.push("💰 نطاق السعر: " + esc(p.maxPrice > 0 ? ps + " — " + p.maxPrice + " ج" : ps));
    }
    if (p.minGp)     lines.push("🎮 الرصيد المطلوب: " + esc(p.minGp));
    if (p.note)      lines.push("📝 ملاحظة: " + esc(p.note));
    lines.push("🕐 " + new Date().toLocaleString("ar-EG"));
    return lines.join("\n");
  },

};

// ─────────────────────────────────────────────────────────────
//  ROUTE: POST /api/notify
//  Called by the frontend for every Telegram notification event.
//  The bot token NEVER leaves the server.
//
//  Body schema:app.post("/api/notify", rateLimitMiddleware, async function (req, res) {
  const { event, seller, data } = req.body;
  
  // تجهيز البيانات
  const clean = {
    event: event || "unknown",
    seller: String(seller || "unknown").substring(0, 50),
    data: typeof data === "object" ? data : { raw: data },
    timestamp: Date.now()
  };

  try {
    // السطر ده هو اللي هيحول الـ null لبيانات في Firebase
    await db.ref("notifications").push(clean);

    // إرسال التليجرام
    const text = `🔔 إشعار جديد\n👤 البائع: ${clean.seller}\n📝 الحدث: ${clean.event}`;
    await sendTelegram(text);

    return res.json({ ok: true });
  } catch (err) {
    console.error("خطأ:", err);
    return res.status(500).json({ ok: false, error: "failed" });
  }
});

//  {
//    eventType : "whatsapp_click" | "waitlist" | "sale" | "account_request"
//    payload   : { ...event-specific fields }
//  }
// ─────────────────────────────────────────────────────────────
app.post("/api/notify", rateLimitMiddleware, async function (req, res) {
  const { eventType, payload } = req.body || {};

  // Validate event type
  const VALID_TYPES = ["whatsapp_click", "waitlist", "sale", "account_request"];
  if (!notEmpty(eventType) || !VALID_TYPES.includes(eventType)) {
    return res.status(400).json({ ok: false, error: "invalid_event_type" });
  }

  if (!payload || typeof payload !== "object") {
    return res.status(400).json({ ok: false, error: "missing_payload" });
  }

  // Sanitize all payload fields — nothing from the client is trusted
  const clean = {
    storeName: sanitize(payload.storeName, 100),
    name:      sanitize(payload.name,      80),
    whatsapp:  sanitize(payload.whatsapp,  20),
    price:     sanitize(String(payload.price  ?? ""), 30),
    profit:    sanitize(String(payload.profit ?? ""), 30),
    players:   sanitize(payload.players,   200),
    note:      sanitize(payload.note,      300),
    minGp:     sanitize(payload.minGp,     60),
    minPrice:  Math.max(0, parseInt(payload.minPrice) || 0),
    maxPrice:  Math.max(0, parseInt(payload.maxPrice) || 0),
  };

  // Build the message using the appropriate template
  const builder = messageBuilders[eventType];
  if (!builder) {
    return res.status(400).json({ ok: false, error: "unknown_event_type" });
  }

  const text = builder(clean);

  // Send via server-side HTTPS (token stays on server)
// حفظ البيانات في فايربيز
await db.ref("notifications").push({ ...clean, timestamp: Date.now() });

  const result = await sendTelegram(text);
  return res.json(result);
});

// ─────────────────────────────────────────────────────────────
//  ROUTE: POST /api/tg-test
//  Admin-only: test that the server-side token is working.
//  Frontend sends NO token — the server uses its own.
// ─────────────────────────────────────────────────────────────
app.post("/api/tg-test", rateLimitMiddleware, async function (req, res) {
  if (!TG_BOT_TOKEN || !TG_CHAT_ID) {
    return res.status(503).json({ ok: false, error: "not_configured" });
  }
  const result = await sendTelegram(
    "✅ <b>اتصال ناجح!</b>\n\nتم ربط بوت تلجرام بستورك على eFootball Store بنجاح."
  );
  return res.json(result);
});

// ─────────────────────────────────────────────────────────────
//  ROUTE: GET /api/health
//  Simple liveness probe. Safe to expose publicly.
// ─────────────────────────────────────────────────────────────
app.get("/api/health", function (_req, res) {
  res.json({
    status: "ok",
    tg:     !!(TG_BOT_TOKEN && TG_CHAT_ID),
    ts:     Date.now(),
  });
});

// ─────────────────────────────────────────────────────────────
//  CATCH-ALL: Unknown routes → 404
// ─────────────────────────────────────────────────────────────
app.use(function (_req, res) {
  res.status(404).json({ ok: false, error: "not_found" });
});

// ─────────────────────────────────────────────────────────────
//  START
// ─────────────────────────────────────────────────────────────
app.listen(PORT, function () {
  console.log(`[eFootball Backend] Listening on port ${PORT}`);
  console.log(`[eFootball Backend] Telegram: ${TG_BOT_TOKEN ? "configured ✓" : "NOT configured ✗"}`);
  console.log(`[eFootball Backend] CORS origin: ${ALLOWED_ORIGIN}`);
});

module.exports = app; // for testing
