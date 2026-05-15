import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import encryptjs from "encryptjs";
import User from "./models/User.mjs";
import { signJWT } from "./Utils/JWT.mjs";

dotenv.config();
const app = express();

app.use(cors({
    origin: "https://login-ecommerce-app.netlify.app",
    methods: ["GET", "POST", "DELETE", "UPDATE"],
    credentials: true
}));
app.use(express.json());

const P_SECRET = process.env.PASSWORD_SECRET || "my_super_secret_key";


mongoose.connect(process.env.MONGO_DB_URI)
    .then(() => console.log(" MongoDB Connected"))
    .catch(err => console.error(" DB Error:", err));


app.post("/signup", async (req, res) => {
    try {
        const { username, password } = req.body;


        const encryptedPassword = encryptjs.encrypt(password, P_SECRET, 256);

        const newUser = new User({
            username,
            password: encryptedPassword
        });

        await newUser.save();
        res.status(201).json({ message: "User Registered Successfully!" });
    } catch (err) {
        res.status(500).json({ message: "Error in Signup", error: err.message });
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
        res.status(500).json({ message: "Server Error", error: err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server is live on port ${PORT}`);
});