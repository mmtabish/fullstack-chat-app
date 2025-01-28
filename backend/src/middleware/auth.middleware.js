import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
export const protectRoute = async (req, res, next) =>{
    try{
        const token = req.cookies.jwt;//get token from cookies

        if(!token){
            return res.status(401).json({message: "Unauthorized-No Token provided"});
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);//verify token

        if(!decoded){
            return res.status(404).json({message: "Unauthorized-Token not found"});
        }

        const user = await User.findById(decoded.userId).select("-password");

        if(!user){
            return res.status(404).json({message: "user not found"});
        }

        req.user = user;//attach user to req object

        next();

    }catch(error){
        console.log("Error in protectRoute", error.message);
        res.status(500).json({message: "Internal server error"});
    }
}