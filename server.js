require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const User = require("./user");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";

app.use(cors({
  origin: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "KF8 Backend is running"
  });
});

app.get("/api/health", async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping();

    res.json({
      success: true,
      database: "connected"
    });
  } catch (error) {
    res.status(503).json({
      success: false,
      database: "disconnected"
    });
  }
});

function makeToken(user) {
  return jwt.sign(
    {
      id: user._id.toString(),
      username: user.username,
      role: user.role || "user"
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function publicUser(user) {
  return {
    id: user._id,
    username: user.username,
    email: user.email,
    role: user.role || "user",
    pts: Number(user.balance || 0),
    balance: Number(user.balance || 0),
    createdAt: user.createdAt
  };
}

function auth(req, res, next) {
  const header = String(req.headers.authorization || "");

  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Authentication required"
    });
  }

  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token"
    });
  }
}

function adminOnly(req, res, next) {
  if (req.auth?.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin access required"
    });
  }

  next();
}


/* =========================
   REGISTER
========================= */

async function registerHandler(req, res) {
  try {
    const username = String(
      req.body.username ||
      req.body.userName ||
      ""
    ).trim();

    const email = String(
      req.body.email || ""
    ).trim().toLowerCase();

    const password = String(
      req.body.password || ""
    );

    if (!/^[A-Za-z0-9._-]{3,24}$/.test(username)) {
      return res.status(400).json({
        success: false,
        message: "Username must be 3-24 characters."
      });
    }

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters."
      });
    }

    const existingUser = await User.findOne({
      $or: [
        { username: username },
        { email: email }
      ]
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Username or email already exists."
      });
    }

    const hashedPassword = await bcrypt.hash(
      password,
      12
    );

    const newUser = new User({
      username: username,
      email: email,
      password: hashedPassword,
      balance: 0,
      role: "user",
      depositHistory: [],
      withdrawalHistory: [],
      transactionHistory: []
    });

    await newUser.save();

    const token = makeToken(newUser);

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      token: token,
      user: publicUser(newUser)
    });

  } catch (error) {

    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Registration failed."
    });
  }
}

app.post("/register", registerHandler);

app.post(
  "/api/auth/register",
  registerHandler
);


/* =========================
   LOGIN
========================= */

async function loginHandler(req, res) {

  try {

    const identity = String(
      req.body.username ||
      req.body.email ||
      req.body.identity ||
      ""
    ).trim();

    const password = String(
      req.body.password || ""
    );

    if (!identity || !password) {

      return res.status(400).json({
        success: false,
        message: "Username/email and password are required."
      });

    }

    const user = await User.findOne({

      $or: [
        {
          username: identity
        },
        {
          email: identity.toLowerCase()
        }
      ]

    });

    if (!user) {

      return res.status(401).json({
        success: false,
        message: "Invalid username/email or password."
      });

    }

    const passwordOK =
      await bcrypt.compare(
        password,
        user.password
      );

    if (!passwordOK) {

      return res.status(401).json({
        success: false,
        message: "Invalid username/email or password."
      });

    }

    const token = makeToken(user);

    res.json({

      success: true,

      message: "Login successful",

      token: token,

      user: publicUser(user)

    });

  } catch (error) {

    console.error(
      "LOGIN ERROR:",
      error
    );

    res.status(500).json({

      success: false,

      message: "Login failed."

    });

  }
}

app.post(
  "/api/auth/login",
  loginHandler
);

app.post(
  "/login",
  loginHandler
);


/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/auth/me",
  auth,
  async (req, res) => {

    try {

      const user =
        await User.findById(
          req.auth.id
        );

      if (!user) {

        return res.status(404).json({
          success: false,
          message: "User not found."
        });

      }

      res.json({

        success: true,

        user: publicUser(user)

      });

    } catch (error) {

      res.status(500).json({

        success: false,

        message: "Unable to load account."

      });

    }

  }
);


/* =========================
   BALANCE
========================= */

app.get(
  "/api/balance",
  auth,
  async (req, res) => {

    try {

      const user =
        await User.findById(
          req.auth.id
        );

      if (!user) {

        return res.status(404).json({
          success: false,
          message: "User not found."
        });

      }

      res.json({

        success: true,

        balance:
          Number(user.balance || 0),

        pts:
          Number(user.balance || 0)

      });

    } catch (error) {

      res.status(500).json({

        success: false,

        message:
          "Unable to load balance."

      });

    }

  }
);


/* =========================
   DEPOSIT
========================= */

async function depositHandler(
  req,
  res
) {

  try {

    const email =
      String(
        req.body.email || ""
      ).trim().toLowerCase();

    const amount =
      Number(req.body.amount);

    const utr =
      String(
        req.body.utr ||
        req.body.UTR ||
        req.body.transactionId ||
        ""
      ).trim();

    if (
      !email ||
      !Number.isFinite(amount) ||
      amount <= 0
    ) {

      return res.status(400).json({

        success: false,

        message:
          "Valid email and amount are required."

      });

    }

    const user =
      await User.findOne({
        email: email
      });

    if (!user) {

      return res.status(404).json({

        success: false,

        message:
          "User not found"

      });

    }

    user.balance =
      Number(user.balance || 0)
      + amount;

    if (!Array.isArray(
      user.depositHistory
    )) {
      user.depositHistory = [];
    }

    if (!Array.isArray(
      user.transactionHistory
    )) {
      user.transactionHistory = [];
    }

    user.depositHistory.push({

      amount: amount,

      utr: utr,

      date: new Date()

    });

    user.transactionHistory.push({

      type: "Deposit",

      amount: amount,

      utr: utr,

      date: new Date()

    });

    await user.save();

    res.json({

      success: true,

      message:
        "Deposit successful",

      balance:
        user.balance

    });

  } catch (error) {

    console.error(
      "DEPOSIT ERROR:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        error.message

    });

  }

}

app.post(
  "/deposit",
  depositHandler
);

app.post(
  "/api/deposit",
  depositHandler
);


/* =========================
   WITHDRAW
========================= */

async function withdrawalHandler(
  req,
  res
) {

  try {

    const email =
      String(
        req.body.email || ""
      ).trim().toLowerCase();

    const amount =
      Number(req.body.amount);

    const utr =
      String(
        req.body.utr ||
        req.body.UTR ||
        req.body.transactionId ||
        ""
      ).trim();

    const upi =
      String(
        req.body.upi ||
        req.body.upiId ||
        ""
      ).trim();

    if (
      !email ||
      !Number.isFinite(amount) ||
      amount <= 0
    ) {

      return res.status(400).json({

        success: false,

        message:
          "Valid email and amount are required."

      });

    }

    const user =
      await User.findOne({
        email: email
      });

    if (!user) {

      return res.status(404).json({

        success: false,

        message:
          "User not found"

      });

    }

    if (
      Number(user.balance || 0)
      < amount
    ) {

      return res.status(400).json({

        success: false,

        message:
          "Insufficient balance"

      });

    }

    user.balance =
      Number(user.balance || 0)
      - amount;

    if (!Array.isArray(
      user.withdrawalHistory
    )) {
      user.withdrawalHistory = [];
    }

    if (!Array.isArray(
      user.transactionHistory
    )) {
      user.transactionHistory = [];
    }

    user.withdrawalHistory.push({

      amount: amount,

      utr: utr,

      upi: upi,

      status: "Pending",

      date: new Date()

    });

    user.transactionHistory.push({

      type: "Withdrawal",

      amount: amount,

      utr: utr,

      upi: upi,

      status: "Pending",

      date: new Date()

    });

    await user.save();

    res.json({

      success: true,

      message:
        "Withdrawal request submitted",

      balance:
        user.balance,

      status:
        "Pending"

    });

  } catch (error) {

    console.error(
      "WITHDRAW ERROR:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        error.message

    });

  }

}

app.post(
  "/withdraw",
  withdrawalHandler
);

app.post(
  "/api/withdraw",
  withdrawalHandler
);

app.post(
  "/api/withdrawal",
  withdrawalHandler
);


/* =========================
   HISTORY
========================= */

app.get(
  "/history/:email",
  async (req, res) => {

    try {

      const email =
        String(
          req.params.email || ""
        ).trim().toLowerCase();

      const user =
        await User.findOne({
          email: email
        });

      if (!user) {

        return res.status(404).json({

          success: false,

          message:
            "User not found"

        });

      }

      res.json({

        success: true,

        balance:
          user.balance,

        depositHistory:
          user.depositHistory || [],

        withdrawalHistory:
          user.withdrawalHistory || [],

        transactionHistory:
          user.transactionHistory || []

      });

    } catch (error) {

      res.status(500).json({

        success: false,

        message:
          error.message

      });

    }

  }
);


/* =========================
   ADMIN USERS
========================= */

app.get(
  "/admin/users",
  adminOnly,
  async (req, res) => {

    try {

      const users =
        await User.find()
        .select("-password");

      res.json({

        success: true,

        totalUsers:
          users.length,

        users:
          users

      });

    } catch (error) {

      res.status(500).json({

        success: false,

        message:
          error.message

      });

    }

  }
);


/* =========================
   ADMIN TRANSFER
========================= */

app.post(
  "/api/admin/transfer",
  adminOnly,
  async (req, res) => {

    try {

      const username =
        String(
          req.body.username || ""
        ).trim();

      const amount =
        Number(req.body.amount);

      const action =
        String(
          req.body.action || "add"
        ).toLowerCase();

      if (
        !username ||
        !Number.isFinite(amount) ||
        amount <= 0
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Username and valid amount are required."

        });

      }

      if (
        !["add", "deduct"]
        .includes(action)
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Action must be add or deduct."

        });

      }

      const user =
        await User.findOne({
          username: username
        });

      if (!user) {

        return res.status(404).json({

          success: false,

          message:
            "User not found."

        });

      }

      const current =
        Number(user.balance || 0);

      const next =
        action === "add"
          ? current + amount
          : current - amount;

      if (next < 0) {

        return res.status(400).json({

          success: false,

          message:
            "Balance cannot go below zero."

        });

      }

      user.balance =
        next;

      if (!Array.isArray(
        user.transactionHistory
      )) {
        user.transactionHistory = [];
      }

      user.transactionHistory.push({

        type:
          action === "add"
            ? "Admin Transfer"
            : "Admin Deduction",

        amount:
          amount,

        status:
          "Completed",

        date:
          new Date()

      });

      await user.save();

      res.json({

        success: true,

        message:
          action === "add"
            ? "Balance added."
            : "Balance deducted.",

        user:
          publicUser(user)

      });

    } catch (error) {

      console.error(
        "ADMIN TRANSFER ERROR:",
        error
      );

      res.status(500).json({

        success: false,

        message:
          error.message

      });

    }

  }
);


/* =========================
   TEST USER MODEL
========================= */

app.get(
  "/test-user-model",
  async (req, res) => {

    try {

      const users =
        await User.find()
        .select("-password");

      res.json({

        success: true,

        users:
          users

      });

    } catch (error) {

      res.status(500).json({

        success: false,

        message:
          error.message

      });

    }

  }
);


/* =========================
   START SERVER
========================= */

async function startServer() {

  try {

    await mongoose.connect(
      process.env.MONGODB_URI
    );

    console.log(
      "MongoDB connected successfully"
    );

    app.listen(
      PORT,
      () => {

        console.log(
          `KF8 Backend running on port ${PORT}`
        );

      }
    );

  } catch (error) {

    console.error(
      "MongoDB connection failed:",
      error.message
    );

    process.exit(1);

  }

}

startServer();
