import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

export const signJWT = (payload) => {
    try{
        
    return jwt.sign(payload, process.env.JWT_SECRETE, { 
        expiresIn: "7d"
     });
     
    }catch(err){
        console.log(error)
    }
};

export const verifyJWT = (token) => {
    try {
        return jwt.verify(token, process.env.JWT_SECRETE);
    } catch (err) {
        return err;
    }
};