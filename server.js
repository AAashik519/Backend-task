const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
require("dotenv").config();
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// CORS configuration for subdomain support
 const allowedOrigins = [
  "http://localhost:5173",
  "https://frontend-task-peach-phi.vercel.app"
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
  })
);


// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("✅ Database connected");
  })
  .catch((error) => {
    console.error("❌ Database connection error:", error.message);
  });

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  shopNames: [{ type: String, required: true }],
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);

// Shop Schema for global uniqueness
const shopSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  createdAt: { type: Date, default: Date.now },
});

const Shop = mongoose.model("Shop", shopSchema);

// JWT Secret
const JWT_SECRET = "your-super-secret-jwt-key-change-in-production";

// Password validation function
const validatePassword = (password) => {
  const minLength = password.length >= 8;
  const hasNumber = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  return minLength && hasNumber && hasSpecialChar;
};

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token =
    req.cookies.authToken || req.headers.authorization?.split(" ")[1];

  console.log("Verifying token from:", req.get("host")); // Debug log
  console.log("Cookies received:", req.cookies); // Debug log
  console.log("Token:", token ? "Present" : "Missing"); // Debug log

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.log("Token verification failed:", error.message); // Debug log
    return res.status(401).json({ message: "Invalid token" });
  }
};

// Routes

// Signup
app.post("/api/signup", async (req, res) => {
  try {
    const { username, password, shopNames } = req.body;

    // Validation
    if (!username || !password || !shopNames || shopNames.length < 3) {
      return res.status(400).json({
        message: "Username, password, and at least 3 shop names are required",
      });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters with at least one number and one special character",
      });
    }

    // Check if username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }

    // Check if any shop names already exist
    const existingShops = await Shop.find({ name: { $in: shopNames } });
    if (existingShops.length > 0) {
      return res.status(400).json({
        message: `Shop name(s) already exist: ${existingShops
          .map((shop) => shop.name)
          .join(", ")}`,
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = new User({
      username,
      password: hashedPassword,
      shopNames,
    });

    await user.save();

    // Create shop entries
    const shopPromises = shopNames.map((shopName) => {
      const shop = new Shop({
        name: shopName,
        owner: user._id,
      });
      return shop.save();
    });

    await Promise.all(shopPromises);

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Signin
app.post("/api/signin", async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Incorrect password" });
    }

    // Create JWT token
    const tokenExpiry = rememberMe ? "7d" : "30m";
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: tokenExpiry }
    );

    // Set cookie with proper domain for subdomain sharing
    const cookieExpiry = rememberMe ? 7 * 24 * 60 * 60 * 1000 : 30 * 60 * 1000;

    console.log("Setting cookie for domain: .localhost"); // Debug log

    res.cookie("authToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: cookieExpiry,
      path: "/",
      ...(process.env.NODE_ENV === "development"
        ? { domain: ".localhost" }
        : {}),
    });

    console.log("Cookie set successfully"); // Debug log

    res.json({
      message: "Login successful",
      user: { username: user.username, shopNames: user.shopNames },
      token: token, // Also send token in response for debugging
    });
  } catch (error) {
    console.error("Signin error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Get user profile
app.get("/api/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ user: { username: user.username, shopNames: user.shopNames } });
  } catch (error) {
    console.error("Profile error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Verify token (for subdomain authentication)
app.get("/api/verify-token", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    console.log("Token verification successful for:", user.username); // Debug log

    res.json({
      valid: true,
      user: { username: user.username, shopNames: user.shopNames },
    });
  } catch (error) {
    console.error("Token verification error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Get shop info
app.get("/api/shop/:shopName", verifyToken, async (req, res) => {
  try {
    const { shopName } = req.params;
    const shop = await Shop.findOne({ name: shopName }).populate(
      "owner",
      "username"
    );

    if (!shop) {
      return res.status(404).json({ message: "Shop not found" });
    }

    res.json({ shop: { name: shop.name, owner: shop.owner.username } });
  } catch (error) {
    console.error("Shop info error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Logout
app.post("/api/logout", (req, res) => {
  res.clearCookie("authToken", {
    domain: ".localhost",
    path: "/",
  });
  res.json({ message: "Logged out successfully" });
});

app.get("/", (req, res) => {
  res.send("Hello Server");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
