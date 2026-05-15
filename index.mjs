import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import encryptjs from "encryptjs";
import User from "./models/User.mjs";
import { signJWT } from "./Utils/JWT.mjs";

dotenv.config();
const app = express();

// --- THE ULTIMATE CORS FIX ---
// Hum origin: "*" use kar rahe hain taake koi bhi request block na ho
app.use(cors({
    origin: "*", 
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

// Roots/Health Check
app.get("/", (req, res) => {
    res.status(200).send("🚀 Backend is up and running!");
});

const P_SECRET = process.env.PASSWORD_SECRET || "my_super_secret_key";

// Database Connection
mongoose.connect(process.env.MONGO_DB_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => console.error("❌ DB Error:", err));

// Signup Route
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }
    next();
});

// Login Route
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user) return res.status(404).json({ message: "User not found" });

        const decryptedPassword = encryptjs.decrypt(user.password, P_SECRET, 256);
        if (password !== decryptedPassword) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }
        
        const token = signJWT({ id: user._id, username: user.username });
        res.status(200).json({
            message: "Login Successful",
            token: token
        });
    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).json({ message: "Server Error", error: err.message });
    }
});

// Port Binding (Crucial for Railway)
const PORT = process.env.PORT || 5050;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server is live on port ${PORT}`);
});