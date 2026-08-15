require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const User = require("./user");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "KF8 Backend is running"
  });
});

app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.json({
        success: false,
        message: "User already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword
    });

    await newUser.save();

    res.json({
      success: true,
      message: "User registered successfully"
    });
  } catch (error) {
    res.json({
      success: false,
      message: error.message
    });
  }
});

app.post("/deposit", async (req, res) => {
  try {
    const { email, amount } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({
        success: false,
        message: "User not found"
      });
    }

    user.balance += Number(amount);

    user.depositHistory.push({
      amount,
      date: new Date()
    });

    user.transactionHistory.push({
      type: "Deposit",
      amount,
      date: new Date()
    });

    await user.save();

    res.json({
      success: true,
      message: "Deposit successful",
      balance: user.balance
    });
  } catch (error) {
    res.json({
      success: false,
      message: error.message
    });
  }
});

app.post("/withdraw", async (req, res) => {
  try {
    const { email, amount } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({
        success: false,
        message: "User not found"
      });
    }

    if (user.balance < Number(amount)) {
      return res.json({
        success: false,
        message: "Insufficient balance"
      });
    }

    user.balance -= Number(amount);

    user.withdrawalHistory.push({
      amount,
      date: new Date()
    });

    user.transactionHistory.push({
      type: "Withdrawal",
      amount,
      date: new Date()
    });

    await user.save();

    res.json({
      success: true,
      message: "Withdrawal successful",
      balance: user.balance
    });
  } catch (error) {
    res.json({
      success: false,
      message: error.message
    });
  }
});

app.get("/history/:email", async (req, res) => {
  try {
    const user = await User.findOne({
      email: req.params.email
    });

    if (!user) {
      return res.json({
        success: false,
        message: "User not found"
      });
    }

    res.json({
      success: true,
      balance: user.balance,
      depositHistory: user.depositHistory,
      withdrawalHistory: user.withdrawalHistory,
      transactionHistory: user.transactionHistory
    });
  } catch (error) {
    res.json({
      success: false,
      message: error.message
    });
  }
});

app.get("/admin/users", async (req, res) => {
  try {
    const users = await User.find();

    res.json({
      success: true,
      totalUsers: users.length,
      users
    });
  } catch (error) {
    res.json({
      success: false,
      message: error.message
    });
  }
});

app.get("/test-user-model", async (req, res) => {
  try {
    const users = await User.find();

    res.json({
      success: true,
      users
    });
  } catch (error) {
    res.json({
      success: false,
      message: error.message
    });
  }
});

async function startServer() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);

    console.log("MongoDB connected successfully");

    app.listen(PORT, () => {
      console.log(`KF8 Backend running on port ${PORT}`);
    });
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
  }
}

startServer();