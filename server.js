import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import fs from "fs/promises";
import mongoose from "mongoose";

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "dern-support-secret-key-2025";
// middleware/verifyToken.js

export function verifyToken(req, res, next) {
  // ⚠️ Vaqtinchalik tokenni tekshirishni o'chirib qo'yamiz
  // Har kim kiraveradi
  req.user = { role: "temp" }; // yoki kerakli rol
  next();
}
export function requireRole(role) {
  return function (req, res, next) {
    // ⚠️ Vaqtinchalik ruxsat beramiz
    req.user = { role }; // Admin, master, user sifatida kiritiladi
    next();
  };
}

// MongoDB ga ulanish (Vercel uchun muhit o'zgaruvchisi orqali)
mongoose.connect(process.env.MONGO_URI, { // <-- Mana bu yerda MONGO_URI ishlatiladi
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB ga ulanish muvaffaqiyatli!'))
.catch(err => console.error('MongoDB ulanishda xato:', err));

// MongoDB shemalari
const UserSchema = new mongoose.Schema({
  id: String,
  username: String,
  email: String,
  password: String,
  fullName: String,
  phone: String,
  role: { type: String, default: "user" },
  createdAt: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true }
});
const User = mongoose.model('User', UserSchema);

const OrderSchema = new mongoose.Schema({
  id: String,
  userId: String,
  items: Array,
  totalAmount: Number,
  status: { type: String, default: 'pending' },
  shippingAddress: String,
  notes: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', OrderSchema);

const ProductSchema = new mongoose.Schema({
  id: String,
  name: String,
  description: String,
  price: Number,
  category: String,
  stock: Number,
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', ProductSchema);

const MasterSchema = new mongoose.Schema({
  id: String,
  fullName: String,
  email: String,
  phone: String,
  specialization: String,
  role: { type: String, default: 'master' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const Master = mongoose.model('Master', MasterSchema);

// Middleware
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));

// File upload konfiguratsiyasi
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = "uploads/";
    try {
      await fs.mkdir(uploadDir, { recursive: true });
    } catch (err) {
      console.error("Uploads papkasi yaratishda xato:", err);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token talab qilinadi" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Yaroqsiz token" });
    }
    req.user = user;
    next();
  });
};

// Home endpoint
app.get("/", async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalOrders = await Order.countDocuments();
    const totalProducts = await Product.countDocuments();

    res.json({
      message: "🚀 DERN Support Backend Server",
      status: "✅ Ishlamoqda",
      time: new Date().toISOString(),
      endpoints: {
        auth: ["POST /api/auth/register", "POST /api/auth/login", "GET /api/auth/me"],
        orders: ["GET /api/orders", "POST /api/orders"],
        products: ["GET /api/products", "POST /api/products"],
        upload: ["POST /api/upload"],
        admin: ["GET /api/admin/stats"],
      },
      stats: {
        users: totalUsers,
        orders: totalOrders,
        products: totalProducts,
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

// AUTHENTICATION
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, firstName, lastName, phone, role } = req.body;

    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({ error: "Email, parol, ism va familiya talab qilinadi" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Bu email allaqachon ro'yxatdan o'tgan" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const totalUsers = await User.countDocuments();
    const newUser = new User({
      id: (totalUsers + 1).toString(),
      username: email.split("@")[0],
      email,
      password: hashedPassword,
      fullName: `${firstName} ${lastName}`,
      phone: phone || "",
      role: totalUsers === 0 ? "admin" : role || "user",
      createdAt: new Date(),
      isActive: true,
    });

    await newUser.save();

    const token = jwt.sign({ id: newUser.id, username: newUser.username, role: newUser.role }, JWT_SECRET, {
      expiresIn: "24h",
    });

    res.status(201).json({
      message: "Muvaffaqiyatli ro'yxatdan o'tdingiz!",
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        fullName: newUser.fullName,
        role: newUser.role,
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email va parol talab qilinadi" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Noto'g'ri login ma'lumotlari" });
    }

    if (!user.isActive) {
      return res.status(401).json({ error: "Hisob bloklangan" });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Noto'g'ri login ma'lumotlari" });
    }

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "24h" });

    res.json({
      message: "Muvaffaqiyatli kirdingiz!",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.id });
    if (!user) {
      return res.status(404).json({ error: "Foydalanuvchi topilmadi" });
    }

    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      phone: user.phone,
      role: user.role,
      createdAt: user.createdAt,
    });
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

// ORDERS
app.post("/api/orders", authenticateToken, async (req, res) => {
  try {
    const { items, totalAmount, shippingAddress, notes } = req.body;

    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Buyurtma elementlari talab qilinadi" });
    }

    const totalOrders = await Order.countDocuments();
    const newOrder = new Order({
      id: (totalOrders + 1).toString(),
      userId: req.user.id,
      items,
      totalAmount: totalAmount || 0,
      status: "pending",
      shippingAddress: shippingAddress || "",
      notes: notes || "",
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await newOrder.save();

    res.status(201).json({
      message: "Buyurtma muvaffaqiyatli yaratildi",
      order: newOrder,
    });
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

app.get("/api/orders", authenticateToken, async (req, res) => {
  try {
    let userOrders;
    if (req.user.role === "admin") {
      userOrders = await Order.find();
      userOrders = await Promise.all(userOrders.map(async (order) => {
        const user = await User.findOne({ id: order.userId });
        return {
          ...order._doc,
          user: user ? { username: user.username, email: user.email } : null,
        };
      }));
    } else {
      userOrders = await Order.find({ userId: req.user.id });
    }
    res.json(userOrders);
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

// PRODUCTS
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

app.post("/api/products", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin huquqi talab qilinadi" });
  }

  try {
    const { name, description, price, category, stock } = req.body;

    if (!name || !price) {
      return res.status(400).json({ error: "Mahsulot nomi va narxi talab qilinadi" });
    }

    const totalProducts = await Product.countDocuments();
    const newProduct = new Product({
      id: (totalProducts + 1).toString(),
      name,
      description: description || "",
      price: Number.parseFloat(price),
      category: category || "other",
      stock: Number.parseInt(stock) || 0,
      isActive: true,
      createdAt: new Date(),
    });

    await newProduct.save();

    res.status(201).json({
      message: "Mahsulot muvaffaqiyatli yaratildi",
      product: newProduct,
    });
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

// MASTERS
app.post("/api/masters", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin" && req.user.role !== "master") {
    return res.status(403).json({ error: "Admin yoki Master huquqi talab qilinadi" });
  }

  try {
    const { fullName, email, phone, specialization } = req.body;

    if (!fullName || !email || !phone || !specialization) {
      return res.status(400).json({ error: "To‘liq ma’lumotlar talab qilinadi" });
    }

    const totalMasters = await Master.countDocuments();
    const newMaster = new Master({
      id: (totalMasters + 1).toString(),
      fullName,
      email,
      phone,
      specialization,
      createdAt: new Date(),
      isActive: true,
    });

    await newMaster.save();

    res.status(201).json({
      message: "Master muvaffaqiyatli qo‘shildi",
      master: newMaster,
    });
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

app.get("/api/masters", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin" && req.user.role !== "master") {
    return res.status(403).json({ error: "Admin yoki Master huquqi talab qilinadi" });
  }

  try {
    const masters = await Master.find();
    res.json(masters);
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

// FILE UPLOAD
app.post("/api/upload", authenticateToken, upload.single("file"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Fayl tanlanmadi" });
    }

    res.json({
      message: "Fayl muvaffaqiyatli yuklandi",
      file: {
        filename: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size,
        url: `/uploads/${req.file.filename}`,
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Fayl yuklashda xato: " + error.message });
  }
});

// USERS
app.get("/api/users", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin huquqi talab qilinadi" });
  }
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

// ADMIN
app.get("/api/admin/stats", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin huquqi talab qilinadi" });
  }

  try {
    const totalUsers = await User.countDocuments();
    const totalOrders = await Order.countDocuments();
    const totalProducts = await Product.countDocuments();
    const pendingOrders = await Order.countDocuments({ status: "pending" });
    const completedOrders = await Order.countDocuments({ status: "delivered" });
    const recentOrders = await Order.find().sort({ createdAt: -1 }).limit(5);

    const stats = {
      totalUsers,
      totalOrders,
      totalProducts,
      pendingOrders,
      completedOrders,
      recentOrders,
    };

    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: "Server xatosi: " + error.message });
  }
});

// Initial users
const initializeUsers = async () => {
  try {
    const userCount = await User.countDocuments();
    if (userCount === 0) {
      const initialUser = new User({
        id: "1",
        username: "admin_user",
        email: "admin@dernsupport.uz",
        password: await bcrypt.hash("admin123", 10),
        fullName: "Admin User",
        role: "admin",
        createdAt: new Date(),
        isActive: true,
      });
      await initialUser.save();

      const initialMaster = new User({
        id: "2",
        username: "master_user",
        email: "master@dernsupport.uz",
        password: await bcrypt.hash("master123", 10),
        fullName: "Master User",
        role: "master",
        createdAt: new Date(),
        isActive: true,
      });
      await initialMaster.save();

      console.log("Initial users created: admin@dernsupport.uz, master@dernsupport.uz");
    }
  } catch (error) {
    console.error("Initial users yaratishda xato:", error);
  }
};

// Start server
app.listen(PORT, async () => {
  await initializeUsers();
  console.log(`🚀 DERN Support Backend Server`);
  console.log(`📡 Port: ${PORT}`);
  console.log(`🏠 Home: http://localhost:${PORT}`);
  console.log(`🔗 API: http://localhost:${PORT}/api`);
  console.log(`⚡ Status: To'liq ishlamoqda`);
});