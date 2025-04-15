require("dotenv").config();
const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");
const multer = require("multer");
const path = require("path");
const axios = require("axios"); // ✅ Import axios
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// const PORT = process.env.PORT || 5000;
// const HOST = "0.0.0.0"; // Allow access from any device on the network

// ✅ Middleware (Must be before routes)
app.use(cors({ origin: "*", methods: ["GET", "POST"], credentials: true }));
app.use(bodyParser.json()); // 👈 Ensures req.body is parsed
app.use(bodyParser.urlencoded({ extended: true }));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ✅ Google Gemini API Key (Securely Stored in .env)
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
console.log("🔑 Google Gemini API Key Loaded:", GEMINI_API_KEY ? "Yes" : "No");

// ✅ Chatbot API Route for Google Gemini 2.0 Flash
app.post("/api/chatbot", async (req, res) => {
  const { message } = req.body;

  if (!GEMINI_API_KEY) {
    return res.status(500).json({ error: "Missing Google Gemini API key" });
  }

  if (!message || typeof message !== "string") {
    return res.status(400).json({ error: "Invalid message input" });
  }

  try {
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`,
      {
        contents: [{ role: "user", parts: [{ text: message }] }],
        generationConfig: {
          temperature: 0.7, // Control response randomness
          topP: 1,
          maxOutputTokens: 100, // Adjust response length
        },
      },
      {
        headers: { "Content-Type": "application/json" },
      }
    );

    // ✅ Extract response from Gemini API
    if (response.data?.candidates?.length > 0) {
      res.json({ reply: response.data.candidates[0].content.parts[0].text });
    } else {
      res.status(500).json({ error: "Invalid response from Gemini API" });
    }
  } catch (error) {
    console.error("❌ Google Gemini API Error:", error.response?.data || error.message);
    res.status(500).json({ error: "Failed to fetch response from Google Gemini API" });
  }
});




// ✅ Serve React Frontend (Build)
app.use(express.static(path.join(__dirname, "frontend")));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "index.html"));
});

// ✅ Database Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "smart_farming",
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err.message);
    process.exit(1);
  }
  console.log("✅ MySQL Connected...");
});

// ✅ Middleware to handle invalid JSON errors
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    console.error("❌ Invalid JSON format received!");
    return res.status(400).json({ message: "Invalid JSON format!" });
  }
  next();
});

// ✅ Test Route
app.get("/", (req, res) => {
  res.send("✅ Backend is running...");
});

// ✅ Global Motor State
let isMotorRunning = false;

// ✅ Handle Sensor Data Posting (Real-time updates)
app.post("/sensor-data", (req, res) => {
  const { temperature, humidity, moisture } = req.body;

  if (temperature === undefined || humidity === undefined || moisture === undefined) {
    return res.status(400).json({ message: "Invalid sensor data received!" });
  }

  db.query(
    "INSERT INTO sensor_data (temperature, humidity, moisture, timestamp) VALUES (?, ?, ?, NOW())",
    [temperature, humidity, moisture],
    (err) => {
      if (err) return res.status(500).json({ message: "Database error" });

      io.emit("sensor-update", { temperature, humidity, moisture });

      if (moisture < 20 && !isMotorRunning) {
        console.log("⚠ Moisture low, starting motor...");
        isMotorRunning = true;
        io.emit("motor-status", { running: true });
      } else if (moisture >= 40 && isMotorRunning) {
        console.log("✅ Moisture sufficient, stopping motor...");
        isMotorRunning = false;
        io.emit("motor-status", { running: false });
      }

      res.json({ message: "✅ Sensor data saved!" });
    }
  );
});

// ✅ Route to Get Latest Sensor Data
app.get("/sensor-data/latest", (req, res) => {
  db.query("SELECT * FROM sensor_data ORDER BY timestamp DESC LIMIT 1", (err, result) => {
    if (err) {
      console.error("❌ Database error:", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.json(result.length ? result[0] : { temperature: 0, humidity: 0, moisture: 0 });
  });
});

// ✅ Start Motor
app.post("/start-motor", (req, res) => {
  if (!isMotorRunning) {
    isMotorRunning = true;
    io.emit("motor-status", { running: true });
    res.json({ message: "🚰 Motor started!" });
  } else {
    res.json({ message: "Motor is already running!" });
  }
});

// ✅ Stop Motor
app.post("/stop-motor", (req, res) => {
  if (isMotorRunning) {
    isMotorRunning = false;
    io.emit("motor-status", { running: false });
    res.json({ message: "🛑 Motor stopped!" });
  } else {
    res.json({ message: "Motor is already stopped!" });
  }
});

// ✅ WebSocket Connection for Real-Time Updates
io.on("connection", (socket) => {
  console.log("🌐 New client connected");

  socket.emit("motor-status", { running: isMotorRunning });

  db.query("SELECT * FROM sensor_data ORDER BY timestamp DESC LIMIT 1", (err, result) => {
    if (!err && result.length) {
      socket.emit("sensor-update", result[0]);
    }
  });

  socket.on("disconnect", () => console.log("Client disconnected"));
});

// ✅ Signup Route
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
  db.query(sql, [name, email, hashedPassword], (err, result) => {
    if (err) return res.status(500).json({ message: "Error inserting user" });

    const token = jwt.sign({ id: result.insertId }, process.env.JWT_SECRET || "secretkey", { expiresIn: "24h" });
    res.json({ token, message: "Signup successful!" });
  });
});

// ✅ Login Route
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], async (err, result) => {
    if (err || result.length === 0) return res.status(401).json({ message: "User not found" });

    const user = result[0];
    if (!(await bcrypt.compare(password, user.password))) return res.status(401).json({ message: "Incorrect password" });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || "secretkey", { expiresIn: "24h" });
    res.json({ token, message: "Login successful" });
  });
});

// ✅ Signout (Account Deletion)
app.post("/signout", (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: "Email is required for account deletion" });
  }

  const deleteUserSQL = "DELETE FROM users WHERE email = ?";
  db.query(deleteUserSQL, [email], (err, result) => {
    if (err) return res.status(500).json({ message: "Error deleting user" });
    if (result.affectedRows === 0) return res.status(404).json({ message: "User not found!" });

    res.json({ message: "Signout successful. Account deleted!" });
  });
});

// ✅ Logout Route
app.post("/logout", (req, res) => {
  res.json({ message: "Logout successful. Redirecting to login..." });
});

// ✅ File Upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// ✅ Community Messages
app.get("/community-messages", (req, res) => {
  const sql = "SELECT * FROM chat_messages ORDER BY timestamp DESC";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ message: "Error fetching messages" });

    const modifiedResults = results.map((msg) => ({
      ...msg,
      file_path: msg.file_path ? `${req.protocol}://${req.get("host")}${msg.file_path}` : null,
    }));
    res.json(modifiedResults);
  });
});

// ✅ Upload Community Messages
app.post("/community-messages", upload.single("file"), (req, res) => {
  const { message, user_id } = req.body;
  const file_path = req.file ? `/uploads/${req.file.filename}` : null;

  if (!message && !file_path) {
    return res.status(400).json({ message: "Message or file required" });
  }

  const sql = "INSERT INTO chat_messages (user_id, message, file_path) VALUES (?, ?, ?)";
  db.query(sql, [user_id, message, file_path], (err) => {
    if (err) return res.status(500).json({ message: "Error saving message" });
    res.json({ message: "Message sent successfully" });
  });
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});