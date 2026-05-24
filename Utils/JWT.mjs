import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || "fallback_default_secure_key";

export const signJWT = (payload) => {
    try {
        return jwt.sign(payload, JWT_SECRET, { 
            expiresIn: "7d"
        });
    } catch (err) {
        console.error("JWT Signing Error:", err);
        return null;
    }
};

export const verifyJWT = (token) => {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (err) {
        console.error("JWT Verification Failed:", err.message);
        return null;
    }
};