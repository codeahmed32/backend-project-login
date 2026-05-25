import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import encryptjs from "encryptjs";
import User from "./models/User.mjs";
import { signJWT } from "./Utils/JWT.mjs";
import jwt from "jsonwebtoken"; 

dotenv.config();
const app = express();

app.use(cors({
    origin: "https://login-signup-project-live.netlify.app",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());

app.get("/", (req, res) => {
    res.status(200).send("Backend is up and running!");
});

const P_SECRET = process.env.PASSWORD_SECRET || "my_super_secret_key";
const JWT_SECRET = process.env.JWT_SECRET || "my_super_secret_key"; 

mongoose.connect(process.env.MONGO_DB_URI)
    .then(() => console.log("📦 MongoDB Connected"))
    .catch(err => console.error("❌ DB Error:", err));


app.get("/verify", async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Access Denied: No Token Provided" });
        }

        const token = authHeader.split(" ")[1];
        
        const decoded = jwt.verify(token, JWT_SECRET);
        
        if (!decoded || !decoded.id) {
            return res.status(401).json({ message: "Invalid Session State Credentials" });
        }

        const user = await User.findById(decoded.id).select("-password");
        if (!user) {
            return res.status(404).json({ message: "User identity does not exist in registry" });
        }

        res.status(200).json({ user });
    } catch (err) {
        console.error("Session Identity Crash Trace:", err.message);
        res.status(401).json({ message: "Session expired or verification token corrupted", error: err.message });
    }
});

app.post("/signup", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: "Username and password are required" });
        }

        const userExists = await User.findOne({ username });
        if (userExists) {
            return res.status(400).json({ message: "Username already exists" });
        }

        const encryptedPassword = encryptjs.encrypt(password, P_SECRET, 256);
        const newUser = new User({
            username,
            password: encryptedPassword
        });

        await newUser.save();
        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        console.error("Signup Error:", err);
        res.status(500).json({ message: "Server Error", error: err.message });
    }
});

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

const PORT = process.env.PORT || 5050;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server is live on port ${PORT}`);
});