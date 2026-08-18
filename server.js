require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const User = require("./user");

const app = express();
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = String(process.env.NODE_ENV || "development").toLowerCase();
const JWT_ISSUER = "kf8-api";
const JWT_AUDIENCE = "kf8-web";

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET is missing or too short. Use at least 32 random characters.");
  process.exit(1);
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
const allowedOrigins = String(process.env.ALLOWED_ORIGINS || "https://8f9b6f.netlify.app")
  .split(",").map(x => x.trim().replace(/\/$/, "")).filter(Boolean);

app.use((req, res, next) => {
  // Security headers without extra npm dependencies.
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("Cross-Origin-Resource-Policy", "same-site");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  if (req.secure || String(req.headers["x-forwarded-proto"] || "").toLowerCase() === "https") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  if (/^\/api\/(auth|admin)/.test(req.path)) {
    res.setHeader("Cache-Control", "no-store, max-age=0");
    res.setHeader("Pragma", "no-cache");
  }
  next();
});

app.use(cors({
  origin: (origin, callback) => {
    // Non-browser/server-to-server requests have no Origin header.
    if (!origin) return callback(null, true);
    const normalized = String(origin).replace(/\/$/, "");
    if (allowedOrigins.includes(normalized)) return callback(null, true);
    return callback(new Error("CORS origin denied"));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept", "Idempotency-Key"],
  maxAge: 86400,
  credentials: false
}));
app.use(express.json({ limit: "64kb", strict: true }));

function hasDangerousKeys(value) {
  if (!value || typeof value !== "object") return false;
  for (const [key, child] of Object.entries(value)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor" || key.startsWith("$") || key.includes(".")) return true;
    if (hasDangerousKeys(child)) return true;
  }
  return false;
}
app.use((req, res, next) => {
  if (hasDangerousKeys(req.body)) return res.status(400).json({ success:false, message:"Invalid request payload." });
  next();
});

// Small in-memory rate limiter. For multiple Render instances, move this to Redis.
const rateBuckets = new Map();
function rateLimit({ windowMs, max, keyPrefix="global" }) {
  return (req, res, next) => {
    const now = Date.now();
    const ip = String(req.ip || req.socket?.remoteAddress || "unknown");
    const key = `${keyPrefix}:${ip}`;
    let row = rateBuckets.get(key);
    if (!row || row.resetAt <= now) row = { count:0, resetAt:now + windowMs };
    row.count += 1; rateBuckets.set(key, row);
    res.setHeader("X-RateLimit-Limit", String(max));
    res.setHeader("X-RateLimit-Remaining", String(Math.max(0, max-row.count)));
    if (row.count > max) {
      const retry = Math.max(1, Math.ceil((row.resetAt-now)/1000));
      res.setHeader("Retry-After", String(retry));
      return res.status(429).json({ success:false, message:"Too many requests. Please try again later." });
    }
    next();
  };
}
const generalLimiter = rateLimit({ windowMs:60_000, max:240, keyPrefix:"general" });
const loginLimiter = rateLimit({ windowMs:15*60_000, max:20, keyPrefix:"login" });
const adminUnlockLimiter = rateLimit({ windowMs:15*60_000, max:8, keyPrefix:"admin-unlock" });
const forgotLimiter = rateLimit({ windowMs:15*60_000, max:5, keyPrefix:"forgot" });
const resetLimiter = rateLimit({ windowMs:15*60_000, max:10, keyPrefix:"reset" });
app.use("/api", generalLimiter);
setInterval(() => {
  const now=Date.now();
  for (const [k,v] of rateBuckets) if (v.resetAt <= now) rateBuckets.delete(k);
  if (rateBuckets.size > 20000) rateBuckets.clear();
}, 5*60_000).unref?.();

/* =========================
   RESULT + BET MODELS
========================= */

const resultSchema = new mongoose.Schema(
  {
    key: { type: String, unique: true, default: "main" },
    dayKey: { type: String, default: "" },
    results: {
      type: [
        {
          baji: Number,
          patti: String,
          single: String,
          declared: Boolean,
          resultAt: String
        }
      ],
      default: []
    }
  },
  { timestamps: true }
);

const Result = mongoose.models.KF8Result || mongoose.model("KF8Result", resultSchema);

const betSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    username: { type: String, required: true },
    baji: { type: Number, required: true, min: 1, max: 8, index: true },
    gameDay: { type: String, default: "", index: true },
    betType: { type: String, enum: ["single", "patti", "jodi"], required: true },
    rawTarget: { type: String, required: true },
    stake: { type: Number, required: true, min: 0.01 },
    multiplier: { type: Number, required: true },
    payout: { type: Number, required: true },
    status: { type: String, enum: ["Pending", "WON", "LOST"], default: "Pending", index: true },
    result: { type: String, default: null },
    createdAt: { type: Date, default: Date.now },
    settledAt: { type: Date, default: null }
  },
  { timestamps: true }
);

const Bet = mongoose.models.KF8Bet || mongoose.model("KF8Bet", betSchema);

/* =========================
   DEMO LEDGER + AUDIT
   Virtual/demo points only.
========================= */
const ledgerSchema = new mongoose.Schema({
  eventKey: { type: String, required: true, unique: true, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  username: { type: String, required: true, index: true },
  type: { type: String, required: true },
  amount: { type: Number, required: true },
  balanceBefore: { type: Number, required: true },
  balanceAfter: { type: Number, required: true },
  referenceId: { type: String, required: true, index: true },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt: { type: Date, default: Date.now, immutable: true }
}, { versionKey: false });
const Ledger = mongoose.models.KF8DemoLedger || mongoose.model("KF8DemoLedger", ledgerSchema);

const auditSchema = new mongoose.Schema({
  actorUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
  actorUsername: { type: String, index: true },
  action: { type: String, required: true, index: true },
  targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
  referenceId: { type: String, index: true },
  ip: String,
  userAgent: String,
  details: { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt: { type: Date, default: Date.now, immutable: true }
}, { versionKey: false });
const AuditLog = mongoose.models.KF8AuditLog || mongoose.model("KF8AuditLog", auditSchema);

async function recordLedger(user, type, delta, referenceId, metadata = {}) {
  const amount = Number(delta || 0);
  const after = Number(user.balance || 0);
  const before = Number((after - amount).toFixed(2));
  const eventKey = `${type}:${String(referenceId)}`;
  try {
    return await Ledger.create({
      eventKey, userId: user._id, username: user.username, type,
      amount: Number(amount.toFixed(2)), balanceBefore: before,
      balanceAfter: after, referenceId: String(referenceId), metadata
    });
  } catch (err) {
    if (err?.code === 11000) return Ledger.findOne({ eventKey }).lean();
    throw err;
  }
}

async function writeAudit(req, action, targetUser, referenceId, details = {}) {
  try {
    await AuditLog.create({
      actorUserId: req.auth?.id,
      actorUsername: req.auth?.username,
      action,
      targetUserId: targetUser?._id,
      referenceId: referenceId ? String(referenceId) : undefined,
      ip: String(req.headers["x-forwarded-for"] || req.ip || "").split(",")[0].trim(),
      userAgent: String(req.headers["user-agent"] || "").slice(0, 300),
      details
    });
  } catch (err) {
    console.error("AUDIT LOG ERROR:", err);
  }
}

/* =========================
   REAL-TIME CONNECTIONS
========================= */

const clients = new Map();

function sendEventToUser(userId, event, data) {
  const set = clients.get(String(userId));
  if (!set) return;
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of set) {
    try { res.write(payload); } catch (_) {}
  }
}

function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const set of clients.values()) {
    for (const res of set) {
      try { res.write(payload); } catch (_) {}
    }
  }
}

/* =========================
   HELPERS
========================= */

function publicUser(user) {
  return {
    id: user._id,
    username: user.username,
    email: user.email,
    role: user.role === "admin" || user.isAdmin ? "admin" : "user",
    isAdmin: Boolean(user.isAdmin || user.role === "admin"),
    pts: Number(user.balance || 0),
    balance: Number(user.balance || 0),
    totalPredictions: Number(user.totalPredictions || 0),
    wins: Number(user.wins || 0),
    losses: Number(user.losses || 0),
    totalBet: Number(user.totalBet || 0),
    createdAt: user.createdAt
  };
}

function makeToken(user) {
  return jwt.sign(
    {
      id: String(user._id),
      username: user.username,
      role: user.role === "admin" || user.isAdmin ? "admin" : "user",
      v: Number(user.tokenVersion || 0)
    },
    JWT_SECRET,
    { expiresIn: "12h", algorithm:"HS256", issuer:JWT_ISSUER, audience:JWT_AUDIENCE }
  );
}

async function auth(req, res, next) {
  const header = String(req.headers.authorization || "");
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return res.status(401).json({ success:false, message:"Authentication required." });
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms:["HS256"], issuer:JWT_ISSUER, audience:JWT_AUDIENCE });
    const liveUser = await User.findById(decoded.id).select("_id username role isAdmin +tokenVersion");
    if (!liveUser || Number(decoded.v || 0) !== Number(liveUser.tokenVersion || 0)) {
      return res.status(401).json({ success:false, message:"Session expired. Please sign in again." });
    }
    req.auth = { ...decoded, role: liveUser.role === "admin" || liveUser.isAdmin ? "admin" : "user" };
    req.authUser = liveUser;
    next();
  } catch (_) {
    return res.status(401).json({ success:false, message:"Invalid or expired token." });
  }
}

async function adminOnly(req, res, next) {
  try {
    const user = await User.findById(req.auth?.id).select("_id username email role isAdmin");
    if (!user || !(user.isAdmin || user.role === "admin")) {
      return res.status(403).json({ success: false, message: "Admin access required." });
    }
    req.adminUser = user;
    next();
  } catch (_) {
    return res.status(403).json({ success: false, message: "Admin access required." });
  }
}

function cleanEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function cleanUsername(value) {
  return String(value || "").trim();
}

function cleanAmount(value) {
  const amount = Number(value);
  return Number.isFinite(amount) && amount > 0 ? Number(amount.toFixed(2)) : null;
}

const BAJI_RESULT_TIMES = {
  1: "10:05",
  2: "11:35",
  3: "13:05",
  4: "14:35",
  5: "16:05",
  6: "17:35",
  7: "19:05",
  8: "20:35"
};

function resultAtForBaji(baji) {
  const value = BAJI_RESULT_TIMES[Number(baji)] || "23:59";
  return value;
}

function indiaNowParts() {
  const parts = new Intl.DateTimeFormat("en-CA", {timeZone:"Asia/Kolkata",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hourCycle:"h23"}).formatToParts(new Date());
  const o = Object.fromEntries(parts.map(p => [p.type,p.value]));
  return {year:+o.year,month:+o.month,day:+o.day,hour:+o.hour,minute:+o.minute};
}
function currentGameDayKey() {
  const p=indiaNowParts(), d=new Date(Date.UTC(p.year,p.month-1,p.day));
  if (p.hour < 8) d.setUTCDate(d.getUTCDate()-1);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}-${String(d.getUTCDate()).padStart(2,"0")}`;
}
function blankResults() {
  return Array.from({length:8},(_,i)=>({baji:i+1,patti:"---",single:"-",declared:false,resultAt:resultAtForBaji(i+1)}));
}

function normalizeResults(results) {
  if (!Array.isArray(results)) return null;
  const rows = results.slice(0, 8).map((r, i) => ({
    baji: Number(r.baji || i + 1),
    patti: String(r.patti || "").replace(/\D/g, "").slice(0, 3),
    single: String(r.single || "").replace(/\D/g, "").slice(0, 1),
    declared: r.declared !== false,
    resultAt: String(r.resultAt || resultAtForBaji(r.baji || i + 1))
  }));

  if (rows.length !== 8) return null;
  if (rows.some(r => r.baji < 1 || r.baji > 8 || r.patti.length !== 3 || r.single.length !== 1)) {
    return null;
  }
  return rows;
}

async function getResults() {
  const dayKey=currentGameDayKey();
  const doc=await Result.findOne({key:"main"}).lean();
  if (!doc || doc.dayKey !== dayKey) {
    const defaults=blankResults();
    await Result.findOneAndUpdate({key:"main"},{$set:{dayKey,results:defaults}},{upsert:true,new:true,setDefaultsOnInsert:true});
    return defaults;
  }
  const byBaji=new Map((doc.results||[]).map(r=>[Number(r.baji),r]));
  return blankResults().map(f=>{const r=byBaji.get(f.baji); return !r?f:{baji:f.baji,patti:String(r.patti||"---"),single:String(r.single||"-"),declared:Boolean(r.declared),resultAt:String(r.resultAt||resultAtForBaji(f.baji))};});
}

function historyView(user) {
  const newestFirst = (rows) => Array.from(rows || []).sort((a, b) =>
    new Date(b?.date || 0).getTime() - new Date(a?.date || 0).getTime()
  );
  return {
    balance: Number(user.balance || 0),
    // These arrays live on the MongoDB User document and are never deleted
    // after approval/rejection/settlement. Only their status is updated.
    depositHistory: newestFirst(user.depositHistory),
    withdrawalHistory: newestFirst(user.withdrawalHistory),
    gameHistory: newestFirst(user.gameHistory),
    transactionHistory: newestFirst(user.transactionHistory)
  };
}

async function notifyUser(user) {
  sendEventToUser(user._id, "account", { user: publicUser(user), history: historyView(user) });
}

setInterval(() => {
  getResults().then(results => broadcast("results",{results})).catch(err => console.error("RESULT DAY ROLLOVER CHECK:",err.message));
},60000).unref?.();

/* =========================
   HEALTH
========================= */

app.get("/", (req, res) => {
  res.json({ success: true, message: "KF8 Backend is running" });
});

app.get("/api/health", async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping();
    res.json({ success: true, database: "connected" });
  } catch (_) {
    res.status(503).json({ success: false, database: "disconnected" });
  }
});

/* =========================
   AUTH
========================= */

async function registerHandler(req, res) {
  try {
    const username = cleanUsername(req.body.username || req.body.userName);
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!/^[A-Za-z0-9._-]{3,24}$/.test(username)) {
      return res.status(400).json({ success: false, message: "Username must be 3-24 characters." });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: "Enter a valid email." });
    }

    if (password.length < 10 || password.length > 128 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
      return res.status(400).json({ success:false, message:"Password must be 10-128 characters and include letters and a number." });
    }

    const existing = await User.findOne({
      $or: [{ username }, { email }]
    });

    if (existing) {
      return res.status(409).json({ success: false, message: "Username or email already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      balance: 0,
      role: "user",
      isAdmin: false
    });

    const token = makeToken(user);
    res.status(201).json({
      success: true,
      message: "User registered successfully.",
      token,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);
    res.status(500).json({ success: false, message: "Registration failed." });
  }
}

app.post("/register", registerHandler);
app.post("/api/auth/register", registerHandler);

async function loginHandler(req, res) {
  try {
    const identity = cleanUsername(req.body.username || req.body.email || req.body.identity);
    const password = String(req.body.password || "");

    if (!identity || !password) {
      return res.status(400).json({ success: false, message: "Username/email and password are required." });
    }

    const user = await User.findOne({
      $or: [
        { username: identity },
        { email: cleanEmail(identity) }
      ]
    }).select("+tokenVersion");

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, message: "Invalid username/email or password." });
    }

    const token = makeToken(user);
    res.json({
      success: true,
      message: "Login successful.",
      token,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({ success: false, message: "Login failed." });
  }
}

app.post("/login", loginLimiter, loginHandler);
app.post("/api/auth/login", loginLimiter, loginHandler);

app.get("/api/auth/me", auth, async (req, res) => {
  const user = await User.findById(req.auth.id);
  if (!user) return res.status(404).json({ success: false, message: "User not found." });
  res.json({ success: true, user: publicUser(user) });
});

async function adminUnlockHandler(req, res) {
  try {
    const password = String(req.body.password || "");
    if (!password) return res.status(400).json({ success: false, message: "Admin password is required." });

    const envUsername = cleanUsername(process.env.ADMIN_USERNAME);
    const query = envUsername
      ? { username: envUsername }
      : { $or: [{ role: "admin" }, { isAdmin: true }] };
    const admin = await User.findOne(query).select("+tokenVersion");

    if (!admin || !(admin.role === "admin" || admin.isAdmin) || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ success: false, message: "Incorrect admin password." });
    }

    const token = makeToken(admin);
    res.json({ success: true, message: "Admin verified.", token, user: publicUser(admin) });
  } catch (error) {
    console.error("ADMIN UNLOCK ERROR:", error);
    res.status(500).json({ success: false, message: "Admin verification failed." });
  }
}

// Canonical admin unlock endpoint + aliases for older hosted HTML builds.
app.post("/api/admin/unlock", adminUnlockLimiter, adminUnlockHandler);
app.post("/api/admin/verify", adminUnlockLimiter, adminUnlockHandler);
app.post("/admin/unlock", adminUnlockLimiter, adminUnlockHandler);

/* =========================
   PASSWORD RESET
========================= */

app.post("/api/auth/forgot-password", forgotLimiter, async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const user = await User.findOne({ email });

    // Do not reveal whether an email exists.
    if (!user) {
      return res.json({ success: true, message: "If the account exists, a verification code has been sent." });
    }

    const otp = String(crypto.randomInt(100000, 1000000));
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

    user.resetOtpHash = otpHash;
    user.resetOtpExpires = new Date(Date.now() + 10 * 60 * 1000);
    user.resetOtpAttempts = 0;
    await user.save();

    if (!process.env.RESEND_API_KEY || !process.env.RESET_FROM_EMAIL) {
      console.warn("Password reset requested but RESEND_API_KEY/RESET_FROM_EMAIL is not configured.");
      return res.status(503).json({
        success: false,
        message: "Password recovery email is not configured on the backend yet."
      });
    }

    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: process.env.RESET_FROM_EMAIL,
        to: [email],
        subject: "Kolkata FF 8 - Password Reset OTP",
        text: `Your Kolkata FF 8 password reset OTP is ${otp}. This OTP expires in 10 minutes. If you did not request this, you can ignore this email.`
      })
    });

    if (!response.ok) {
      console.error("RESET EMAIL ERROR:", await response.text());
      return res.status(502).json({ success: false, message: "Unable to send the reset email." });
    }

    res.json({ success: true, message: "6-digit OTP sent to your registered Gmail. It expires in 10 minutes." });
  } catch (error) {
    console.error("FORGOT PASSWORD ERROR:", error);
    res.status(500).json({ success: false, message: "Password recovery failed." });
  }
});

app.post("/api/auth/reset-password", resetLimiter, async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const otp = String(req.body.otp || "").trim();
    const newPassword = String(req.body.newPassword || "");

    if (!email || !/^\d{6}$/.test(otp) || newPassword.length < 10 || newPassword.length > 128 || !/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword)) {
      return res.status(400).json({ success:false, message:"Invalid reset details." });
    }

    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    const user = await User.findOne({ email }).select("+resetOtpHash +resetOtpExpires +resetOtpAttempts +tokenVersion");

    const expired = !user?.resetOtpExpires || user.resetOtpExpires <= new Date();
    const locked = Number(user?.resetOtpAttempts || 0) >= 5;
    let matches = false;
    if (user?.resetOtpHash && !expired && !locked) {
      const a = Buffer.from(String(user.resetOtpHash), "hex");
      const b = Buffer.from(String(otpHash), "hex");
      matches = a.length === b.length && crypto.timingSafeEqual(a, b);
    }
    if (!user || expired || locked || !matches) {
      if (user && !expired && !locked) {
        user.resetOtpAttempts = Number(user.resetOtpAttempts || 0) + 1;
        await user.save().catch(() => {});
      }
      return res.status(400).json({ success:false, message:"Invalid or expired verification code." });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    user.resetOtpHash = null;
    user.resetOtpExpires = null;
    user.resetOtpAttempts = 0;
    user.tokenVersion = Number(user.tokenVersion || 0) + 1; // logout every existing session
    await user.save();

    res.json({ success: true, message: "Password reset successfully." });
  } catch (error) {
    console.error("RESET PASSWORD ERROR:", error);
    res.status(500).json({ success: false, message: "Password reset failed." });
  }
});

/* =========================
   REAL-TIME EVENTS
========================= */

app.get("/api/events", async (req, res) => {
  const token = String(req.query.token || "");
  if (!token) return res.status(401).end();

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET, { algorithms:["HS256"], issuer:JWT_ISSUER, audience:JWT_AUDIENCE });
    const liveUser = await User.findById(decoded.id).select("_id +tokenVersion");
    if (!liveUser || Number(decoded.v || 0) !== Number(liveUser.tokenVersion || 0)) return res.status(401).end();
  } catch (_) {
    return res.status(401).end();
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  const userId = String(decoded.id);
  if (!clients.has(userId)) clients.set(userId, new Set());
  clients.get(userId).add(res);

  res.write(`event: connected\ndata: ${JSON.stringify({ success: true })}\n\n`);

  try {
    const user = await User.findById(userId);
    if (user) sendEventToUser(userId, "account", { user: publicUser(user), history: historyView(user) });
    const results = await getResults();
    res.write(`event: results\ndata: ${JSON.stringify({ results })}\n\n`);
  } catch (_) {}

  const heartbeat = setInterval(() => {
    try { res.write(": heartbeat\n\n"); } catch (_) {}
  }, 20000);

  req.on("close", () => {
    clearInterval(heartbeat);
    const set = clients.get(userId);
    if (set) {
      set.delete(res);
      if (!set.size) clients.delete(userId);
    }
  });
});

/* =========================
   BALANCE + HISTORY
========================= */

app.get("/api/balance", auth, async (req, res) => {
  const user = await User.findById(req.auth.id);
  if (!user) return res.status(404).json({ success: false, message: "User not found." });
  res.json({ success: true, balance: Number(user.balance || 0), pts: Number(user.balance || 0) });
});

app.get("/api/history", auth, async (req, res) => {
  const user = await User.findById(req.auth.id);
  if (!user) return res.status(404).json({ success: false, message: "User not found." });
  res.json({ success: true, ...historyView(user) });
});

app.get("/api/ledger", auth, async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 200);
  const entries = await Ledger.find({ userId: req.auth.id })
    .sort({ createdAt: -1 })
    .limit(limit)
    .lean();
  res.json({ success: true, entries });
});

app.get("/api/admin/audit-log", auth, adminOnly, async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
  const entries = await AuditLog.find({})
    .sort({ createdAt: -1 })
    .limit(limit)
    .lean();
  res.json({ success: true, entries });
});


// Kept only as a compatibility route; it still requires the logged-in user.
app.get("/history/:email", auth, async (req, res) => {
  const requested = cleanEmail(req.params.email);
  const user = await User.findById(req.auth.id);
  if (!user || user.email !== requested) {
    return res.status(403).json({ success: false, message: "You can only view your own history." });
  }
  res.json({ success: true, ...historyView(user) });
});

/* =========================
   DEPOSIT REQUESTS
========================= */

app.post("/api/deposit", auth, async (req, res) => {
  try {
    const amount = cleanAmount(req.body.amount);
    const utr = String(req.body.utr || req.body.UTR || req.body.transactionId || "").trim();

    if (!amount || amount < 100 || utr.length < 6) {
      return res.status(400).json({ success: false, message: "Minimum demo deposit is 100 PTS and a valid reference is required." });
    }

    const duplicateUtr = await User.findOne({
      _id: req.auth.id,
      depositHistory: { $elemMatch: { utr, status: { $in: ["Pending", "Approved"] } } }
    }).lean();
    if (duplicateUtr) {
      return res.status(409).json({ success: false, message: "This demo deposit reference has already been used." });
    }

    const user = await User.findById(req.auth.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found." });

    if (!Array.isArray(user.depositHistory)) user.depositHistory = [];
    if (!Array.isArray(user.transactionHistory)) user.transactionHistory = [];

    const requestId = new mongoose.Types.ObjectId().toString();
    const item = {
      id: requestId,
      type: "Deposit",
      amount,
      utr,
      status: "Pending",
      details: "UPI deposit request",
      date: new Date()
    };

    user.depositHistory.unshift(item);
    user.transactionHistory.unshift(item);
    await user.save();

    sendEventToUser(user._id, "account", { user: publicUser(user), history: historyView(user) });
    broadcast("admin-data", { type: "deposit-created" });

    res.status(201).json({
      success: true,
      message: "Deposit request submitted.",
      request: item,
      balance: Number(user.balance || 0)
    });
  } catch (error) {
    console.error("DEPOSIT ERROR:", error);
    res.status(500).json({ success: false, message: "Deposit request failed." });
  }
});

/* =========================
   WITHDRAWAL REQUESTS
========================= */

app.post("/api/withdrawal", auth, async (req, res) => {
  try {
    const amount = cleanAmount(req.body.amount);
    const upi = String(req.body.upi || req.body.upiId || "").trim();

    if (!amount || amount < 100 || !upi) {
      return res.status(400).json({ success: false, message: "Minimum demo withdrawal is 100 PTS and a valid UPI ID is required." });
    }

    const user = await User.findById(req.auth.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found." });

    if (Number(user.balance || 0) < amount) {
      return res.status(400).json({ success: false, message: "Insufficient balance." });
    }

    const pendingWithdrawal = (user.withdrawalHistory || []).find(
      x => String(x.status).toLowerCase() === "pending"
    );
    if (pendingWithdrawal) {
      return res.status(409).json({ success: false, message: "A demo withdrawal is already pending." });
    }

    user.balance = Number((Number(user.balance || 0) - amount).toFixed(2));

    if (!Array.isArray(user.withdrawalHistory)) user.withdrawalHistory = [];
    if (!Array.isArray(user.transactionHistory)) user.transactionHistory = [];

    const requestId = new mongoose.Types.ObjectId().toString();
    // Deliberately do NOT store UTR/transactionId for withdrawals.
    const item = {
      id: requestId,
      type: "Withdrawal",
      amount,
      upi,
      status: "Pending",
      details: "UPI withdrawal request",
      date: new Date()
    };

    user.withdrawalHistory.unshift(item);
    user.transactionHistory.unshift(item);
    await user.save();

    sendEventToUser(user._id, "account", { user: publicUser(user), history: historyView(user) });
    broadcast("admin-data", { type: "withdrawal-created" });

    res.status(201).json({
      success: true,
      message: "Withdrawal request submitted.",
      request: item,
      balance: Number(user.balance || 0)
    });
  } catch (error) {
    console.error("WITHDRAW ERROR:", error);
    res.status(500).json({ success: false, message: "Withdrawal request failed." });
  }
});


/* Game entry lock: block bets after closing time */
const BAJI_CLOSE_MINUTES = {
  1: 10 * 60,
  2: 11 * 60 + 30,
  3: 13 * 60,
  4: 14 * 60 + 30,
  5: 16 * 60,
  6: 17 * 60 + 30,
  7: 19 * 60,
  8: 20 * 60 + 30
};

function indiaClockMinutes() {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata", hour: "2-digit", minute: "2-digit", hourCycle: "h23"
  }).formatToParts(new Date());
  const hour = Number(parts.find(p => p.type === "hour")?.value || 0);
  const minute = Number(parts.find(p => p.type === "minute")?.value || 0);
  return hour * 60 + minute;
}

function isGameClosed(baji) {
  const closeMinutes = BAJI_CLOSE_MINUTES[Number(baji)];
  if (!Number.isFinite(closeMinutes)) return true;
  return indiaClockMinutes() >= closeMinutes;
}

/* =========================
   BETS
========================= */

app.post("/api/bets", auth, async (req, res) => {
  try {
    const baji = Number(req.body.baji);
    if (isGameClosed(baji)) {
      return res.status(403).json({ success: false, message: `Baji ${baji} is closed. Entry is not allowed now.` });
    }
    const betType = String(req.body.betType || "").toLowerCase();
    const rawTarget = String(req.body.rawTarget ?? req.body.target ?? "").trim();
    const stake = cleanAmount(req.body.stake);

    const multipliers = { single: 9, patti: 90, jodi: 90 };
    if (!Number.isInteger(baji) || baji < 1 || baji > 8 || !multipliers[betType] || !stake || !rawTarget) {
      return res.status(400).json({ success: false, message: "Invalid bet details." });
    }

    if (
      (betType === "single" && !/^\d$/.test(rawTarget)) ||
      (betType === "patti" && !/^\d{3}$/.test(rawTarget)) ||
      (betType === "jodi" && !/^\d{2}$/.test(rawTarget))
    ) {
      return res.status(400).json({ success: false, message: "Invalid target." });
    }

    const user = await User.findById(req.auth.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found." });

    if (Number(user.balance || 0) < stake) {
      return res.status(400).json({ success: false, message: "Insufficient balance." });
    }

    user.balance = Number((Number(user.balance || 0) - stake).toFixed(2));
    user.totalPredictions = Number(user.totalPredictions || 0) + 1;
    user.totalBet = Number((Number(user.totalBet || 0) + stake).toFixed(2));

    const multiplier = multipliers[betType];
    const bet = await Bet.create({
      userId: user._id,
      username: user.username,
      baji,
      gameDay: currentGameDayKey(),
      betType:
      rawTarget,
      stake,
      multiplier,
      payout: Number((stake * multiplier).toFixed(2))
    });

    if (!Array.isArray(user.transactionHistory)) user.transactionHistory = [];
    if (!Array.isArray(user.gameHistory)) user.gameHistory = [];
    const gameHistoryItem = {
      id: String(bet._id),
      type: "Bet Placed",
      amount: -stake,
      status: "Pending",
      baji,
      betType,
      rawTarget,
      stake,
      payout: bet.payout,
      details: `Kolkata FF 8 Baji ${baji}`,
      date: new Date()
    };
    // Store the same activity in the general ledger-style history and in a
    // dedicated permanent game history for the user's profile.
    user.transactionHistory.unshift(gameHistoryItem);
    user.gameHistory.unshift({ ...gameHistoryItem });

    await user.save();
    await recordLedger(user, "DEMO_BET", -stake, String(bet._id), {
      baji, betType, target: rawTarget, demo: true
    });
    await notifyUser(user);

    res.status(201).json({
      success: true,
      message: "Bet placed.",
      bet,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("BET ERROR:", error);
    res.status(500).json({ success: false, message: "Bet could not be placed." });
  }
});

/* =========================
   RESULTS
========================= */

app.get("/api/results", async (req, res) => {
  const results = await getResults();
  res.json({ success: true, results });
});

app.get("/api/latest-results", async (req, res) => {
  const results = await getResults();
  res.json({ success: true, results });
});

async function settleBaji(baji, patti, single) {
  const dayKey=currentGameDayKey();
  const [y,m,d]=dayKey.split("-").map(Number);
  const start=new Date(Date.UTC(y,m-1,d,2,30,0)), end=new Date(start.getTime()+86400000);
  const bets=await Bet.find({baji,status:"Pending",$or:[{gameDay:dayKey},{gameDay:{$in:["",null]},createdAt:{$gte:start,$lt:end}}]});
  let winners = 0;

  for (const bet of bets) {
    let won = false;

    if (bet.betType === "single") won = bet.rawTarget === single;
    if (bet.betType === "patti") won = bet.rawTarget === patti;
    // Jodi settlement is only possible if a 2-digit jodi is supplied with the result.
    if (bet.betType === "jodi") won = false;

    const user = await User.findById(bet.userId);
    if (!user) continue;

    const historyItem = user.transactionHistory.id ? user.transactionHistory.id(String(bet._id)) : null;

    if (won) {
      user.balance = Number((Number(user.balance || 0) + Number(bet.payout || 0)).toFixed(2));
      user.wins = Number(user.wins || 0) + 1;
      bet.status = "WON";
      bet.result = `${patti}/${single}`;
      bet.settledAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(bet._id));
      if (tx) {
        tx.status = "WON";
        tx.amount = Number(bet.payout || 0);
        tx.details = `Won ${bet.multiplier}x`;
      }
      const gx = (user.gameHistory || []).find(x => String(x.id) === String(bet._id));
      if (gx) {
        gx.status = "WON";
        gx.amount = Number(bet.payout || 0);
        gx.details = `Won ${bet.multiplier}x`;
      }
      winners++;
    } else {
      user.losses = Number(user.losses || 0) + 1;
      bet.status = "LOST";
      bet.result = `${patti}/${single}`;
      bet.settledAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(bet._id));
      if (tx) {
        tx.status = "LOST";
        tx.details = "Bet lost";
      }
      const gx = (user.gameHistory || []).find(x => String(x.id) === String(bet._id));
      if (gx) {
        gx.status = "LOST";
        gx.details = "Bet lost";
      }
    }

    await user.save();
    if (won) {
      await recordLedger(user, "DEMO_WIN", Number(bet.payout || 0), String(bet._id), {
        baji: bet.baji, betType: bet.betType, result: bet.result, demo: true
      });
    }
    await bet.save();
    await notifyUser(user);
  }

  return winners;
}

app.post("/api/admin/results", auth, adminOnly, async (req, res) => {
  try {
    const baji = Number(req.body.baji);
    const patti = String(req.body.patti || "").replace(/\D/g, "").slice(0, 3);
    const single = String(req.body.single || "").replace(/\D/g, "").slice(0, 1);

    if (!Number.isInteger(baji) || baji < 1 || baji > 8 || patti.length !== 3 || single.length !== 1) {
      return res.status(400).json({ success: false, message: "Valid Baji, Patti and Single are required." });
    }

    const current = await getResults();
    const next = current.map((r, i) =>
      Number(r.baji) === baji
        ? { baji, patti, single, declared: true, resultAt: String(r.resultAt || resultAtForBaji(baji)) }
        : { ...r, baji: Number(r.baji || i + 1) }
    );

    await Result.findOneAndUpdate(
      { key: "main" },
      { $set: { dayKey: currentGameDayKey(), results: next } },
      { upsert: true, new: true }
    );

    const winners = await settleBaji(baji, patti, single);

    broadcast("results", { results: next });
    broadcast("admin-data", { type: "result-updated", baji });

    res.json({
      success: true,
      message: `Baji ${baji} result updated.`,
      results: next,
      winners
    });
  } catch (error) {
    console.error("ADMIN RESULT ERROR:", error);
    res.status(500).json({ success: false, message: "Result update failed." });
  }
});

app.post("/api/admin/latest-results", auth, adminOnly, async (req, res) => {
  try {
    const rows = normalizeResults(req.body.results);
    if (!rows) return res.status(400).json({ success: false, message: "Exactly 8 valid results are required." });

    const previous = await getResults();
    await Result.findOneAndUpdate(
      { key: "main" },
      { $set: { dayKey: currentGameDayKey(), results: rows } },
      { upsert: true, new: true }
    );
    for (const row of rows) {
      const old = previous.find(x => Number(x.baji) === Number(row.baji));
      if (!old?.declared || old.patti !== row.patti || old.single !== row.single) {
        await settleBaji(Number(row.baji), String(row.patti), String(row.single));
      }
    }
    broadcast("results", { results: rows });
    broadcast("admin-data", { type: "results-updated" });

    res.json({ success: true, results: rows });
  } catch (error) {
    console.error("LATEST RESULTS ERROR:", error);
    res.status(500).json({ success: false, message: "Latest results update failed." });
  }
});

/* =========================
   ADMIN DATA
========================= */

app.get("/api/admin/users", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("-password -resetOtpHash -resetOtpExpires").sort({ createdAt: -1 });
  res.json({ success: true, totalUsers: users.length, users: users.map(publicUser) });
});

app.get("/admin/users", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("-password -resetOtpHash -resetOtpExpires").sort({ createdAt: -1 });
  res.json({ success: true, totalUsers: users.length, users });
});

app.get("/api/admin/deposits", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("username email depositHistory");
  const requests = [];
  for (const user of users) {
    for (const item of user.depositHistory || []) {
      if (String(item.status).toLowerCase() === "pending") {
        requests.push({
          id: item.id,
          username: user.username,
          email: user.email,
          amount: Number(item.amount || 0),
          utr: item.utr || "",
          status: item.status,
          date: item.date
        });
      }
    }
  }
  requests.sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json({ success: true, requests });
});

app.get("/api/admin/withdrawals", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("username email withdrawalHistory");
  const requests = [];
  for (const user of users) {
    for (const item of user.withdrawalHistory || []) {
      if (String(item.status).toLowerCase() === "pending") {
        requests.push({
          id: item.id,
          username: user.username,
          email: user.email,
          amount: Number(item.amount || 0),
          upi: item.upi || "",
          status: item.status,
          date: item.date
        });
      }
    }
  }
  requests.sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json({ success: true, requests });
});

// Compatibility aliases for older frontend builds.
app.get("/api/admin/deposit-requests", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("username email depositHistory");
  const requests = [];
  for (const user of users) for (const item of user.depositHistory || []) {
    if (String(item.status).toLowerCase() === "pending") requests.push({
      id: item.id, username: user.username, email: user.email, amount: Number(item.amount || 0),
      utr: item.utr || "", status: item.status, date: item.date
    });
  }
  requests.sort((a,b)=>new Date(b.date)-new Date(a.date));
  res.json({success:true, requests});
});

app.get("/api/admin/withdrawal-requests", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("username email withdrawalHistory");
  const requests = [];
  for (const user of users) for (const item of user.withdrawalHistory || []) {
    if (String(item.status).toLowerCase() === "pending") requests.push({
      id: item.id, username: user.username, email: user.email, amount: Number(item.amount || 0),
      upi: item.upi || "", status: item.status, date: item.date
    });
  }
  requests.sort((a,b)=>new Date(b.date)-new Date(a.date));
  res.json({success:true, requests});
});

async function findHistoryOwner(historyName, requestId) {
  // IMPORTANT: load the FULL user document. The old code selected only the
  // history array, which made user.balance look like 0 during admin approval.
  // That caused e.g. 400 + 300 to become 300.
  const user = await User.findOne({ [`${historyName}.id`]: String(requestId) });
  if (!user) return null;
  const item = (user[historyName] || []).find(x => String(x.id) === String(requestId));
  return item ? { user, item } : null;
}

app.post("/api/admin/deposits/:requestId", auth, adminOnly, async (req, res) => {
  try {
    const action = String(req.body.action || "").toLowerCase();
    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ success: false, message: "Action must be approve or reject." });
    }

    const found = await findHistoryOwner("depositHistory", req.params.requestId);
    if (!found) return res.status(404).json({ success: false, message: "Deposit request not found." });

    const { user, item } = found;
    if (!Array.isArray(user.transactionHistory)) user.transactionHistory = [];
    if (!Array.isArray(user.depositHistory)) user.depositHistory = [];
    const currentStatus = String(item.status || "").toLowerCase();
    // Idempotent demo admin action: a second click on an already-approved
    // request must not add the amount a second time. It simply returns the
    // current saved balance instead of showing a red "already processed" error.
    if (currentStatus !== "pending") {
      if (action === "approve" && currentStatus === "approved") {
        return res.json({
          success: true,
          alreadyProcessed: true,
          message: "Deposit already approved; no duplicate credit was added.",
          user: publicUser(user),
          request: item
        });
      }
      return res.status(409).json({ success: false, message: "Deposit request already processed." });
    }

    if (action === "approve") {
      const before = Number(user.balance || 0);
      const amount = Number(item.amount || 0);
      // Demo points are additive: old balance is preserved and the approved
      // deposit is added on top (e.g. 400 + 300 = 700).
      user.balance = Number((before + amount).toFixed(2));
      item.status = "Approved";
      item.details = "Deposit approved by admin";
      item.reviewedAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(item.id));
      if (tx) {
        tx.status = "Approved";
        tx.details = "Deposit approved by admin";
      }
    } else {
      item.status = "Rejected";
      item.details = "Deposit rejected by admin";
      item.reviewedAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(item.id));
      if (tx) {
        tx.status = "Rejected";
        tx.details = "Deposit rejected by admin";
      }
    }

    await user.save();
    if (action === "approve") {
      await recordLedger(user, "DEMO_DEPOSIT", Number(item.amount || 0), String(item.id), {
        utr: item.utr || "", demo: true
      });
    }
    await writeAudit(req, `DEMO_DEPOSIT_${action.toUpperCase()}`, user, item.id, {
      amount: Number(item.amount || 0), demo: true
    });
    await notifyUser(user);
    broadcast("admin-data", { type: "deposit-processed" });

    res.json({ success: true, message: `Deposit ${action}ed.`, user: publicUser(user), request: item });
  } catch (error) {
    console.error("ADMIN DEPOSIT ERROR:", error);
    res.status(500).json({ success: false, message: "Deposit processing failed." });
  }
});

app.post("/api/admin/withdrawals/:requestId", auth, adminOnly, async (req, res) => {
  try {
    const action = String(req.body.action || "").toLowerCase();
    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ success: false, message: "Action must be approve or reject." });
    }

    const found = await findHistoryOwner("withdrawalHistory", req.params.requestId);
    if (!found) return res.status(404).json({ success: false, message: "Withdrawal request not found." });

    const { user, item } = found;
    if (!Array.isArray(user.transactionHistory)) user.transactionHistory = [];
    if (!Array.isArray(user.withdrawalHistory)) user.withdrawalHistory = [];
    if (String(item.status).toLowerCase() !== "pending") {
      return res.status(409).json({ success: false, message: "Withdrawal request already processed." });
    }

    if (action === "reject") {
      user.balance = Number((Number(user.balance || 0) + Number(item.amount || 0)).toFixed(2));
      item.status = "Rejected";
      item.details = "Withdrawal rejected; amount refunded";
      item.reviewedAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(item.id));
      if (tx) {
        tx.status = "Refunded";
        tx.details = "Withdrawal rejected; amount refunded";
        tx.amount = Number(item.amount || 0);
      }
    } else {
      item.status = "Approved";
      item.details = "Withdrawal approved by admin";
      item.reviewedAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(item.id));
      if (tx) {
        tx.status = "Approved";
        tx.details = "Withdrawal approved by admin";
      }
    }

    await user.save();
    if (action === "reject") {
      await recordLedger(user, "DEMO_WITHDRAWAL_REFUND", Number(item.amount || 0), String(item.id), {
        reason: "Admin rejected demo withdrawal; balance refunded", demo: true
      });
    }
    await writeAudit(req, `DEMO_WITHDRAWAL_${action.toUpperCase()}`, user, item.id, {
      amount: Number(item.amount || 0), demo: true
    });
    await notifyUser(user);
    broadcast("admin-data", { type: "withdrawal-processed" });

    res.json({ success: true, message: action === "approve" ? "Withdrawal approved." : "Withdrawal rejected.", user: publicUser(user), request: item });
  } catch (error) {
    console.error("ADMIN WITHDRAWAL ERROR:", error);
    res.status(500).json({ success: false, message: "Withdrawal processing failed." });
  }
});

/* =========================
   ADMIN BALANCE TRANSFER
========================= */

app.post("/api/admin/transfer", auth, adminOnly, async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);
    const amount = cleanAmount(req.body.amount);
    const action = String(req.body.action || "add").toLowerCase();

    if (!username || !amount || !["add", "deduct"].includes(action)) {
      return res.status(400).json({ success: false, message: "Username, valid amount and action are required." });
    }

    const user = await User.findOne({ username: { $regex: new RegExp("^" + username.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$", "i") } });
    if (!user) return res.status(404).json({ success: false, message: "User not found." });

    const current = Number(user.balance || 0);
    const next = action === "add" ? current + amount : current - amount;

    if (next < 0) {
      return res.status(400).json({ success: false, message: "Balance cannot go below zero." });
    }

    user.balance = Number(next.toFixed(2));

    const tx = {
      id: new mongoose.Types.ObjectId().toString(),
      type: action === "add" ? "Admin Transfer" : "Admin Deduction",
      amount: action === "add" ? amount : -amount,
      status: "Completed",
      details: `Admin ${action === "add" ? "added" : "deducted"} balance`,
      date: new Date()
    };

    user.transactionHistory.unshift(tx);
    await user.save();
    await recordLedger(
      user,
      "DEMO_ADJUSTMENT",
      action === "add" ? amount : -amount,
      `admin-transfer:${tx.id}`,
      { action, demo: true }
    );
    await writeAudit(req, `DEMO_BALANCE_${action.toUpperCase()}`, user, tx.id, {
      amount, demo: true
    });
    await notifyUser(user);

    res.json({
      success: true,
      message: action === "add" ? "Demo balance added." : "Demo balance deducted.",
      user: publicUser(user)
    });
  } catch (error) {
    console.error("ADMIN TRANSFER ERROR:", error);
    res.status(500).json({ success: false, message: "Balance update failed." });
  }
});

/* =========================
   ADMIN BOOTSTRAP
========================= */

async function ensureAdmin() {
  const username = cleanUsername(process.env.ADMIN_USERNAME);
  const password = String(process.env.ADMIN_PASSWORD || "");
  const email = cleanEmail(process.env.ADMIN_EMAIL);

  if (!username || !password || !email) {
    console.warn("ADMIN_USERNAME/ADMIN_PASSWORD/ADMIN_EMAIL not configured; existing admin users can still log in.");
    return;
  }

  const existing = await User.findOne({ username });

  if (!existing) {
    const hash = await bcrypt.hash(password, 12);
    await User.create({
      username,
      email,
      password: hash,
      role: "admin",
      isAdmin: true
    });
    console.log("Admin account created from environment variables.");
    return;
  }

  existing.role = "admin";
  existing.isAdmin = true;
  existing.email = email;

  // Keep the Render ADMIN_PASSWORD authoritative, but only re-hash when
  // the configured password is actually different from the stored hash.
  const passwordMatches = await bcrypt.compare(password, existing.password);
  if (!passwordMatches) {
    existing.password = await bcrypt.hash(password, 12);
    console.log("Admin password synchronized from environment variables.");
  }

  await existing.save();
}

// Hide internal stack traces and normalize malformed JSON/CORS failures.
app.use((err, req, res, next) => {
  if (err?.type === "entity.parse.failed") return res.status(400).json({ success:false, message:"Invalid JSON." });
  if (String(err?.message || "").includes("CORS origin denied")) return res.status(403).json({ success:false, message:"Origin not allowed." });
  console.error("UNHANDLED REQUEST ERROR:", err?.message || err);
  return res.status(500).json({ success:false, message:"Request failed." });
});

/* =========================
   START
========================= */

async function startServer() {
  try {
    if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI is missing in Render Environment.");
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB connected successfully.");

    await ensureAdmin();
    await getResults();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`KF8 Backend running on port ${PORT}`);
    });
  } catch (error) {
    console.error("STARTUP ERROR:", error.message);
    process.exit(1);
  }
}

startServer();
