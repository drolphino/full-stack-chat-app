import jwt from "jsonwebtoken"
import User from "../models/user.model.js"

export const protectRoute = async (req,res,next) =>{
    try {
        const token = req.cookies.jwt;
        if(!token) {
            return res.status(401).json({ msg:"Unauthorised-no token provided "});
        }

        const decode = jwt.verify(token, process.env.JWT_SECRET);

        if(!decode){
            return res.status(401).json({ msg: " Unauthorised- Invalid Token"});
        }

        const user = await User.findById(decode.userId).select("-password");

        if(!user) {
            res.status(401).json({msg:"User not found"});
        }

        req.user = user;
        next();
    } catch (error) {
        console.log("Error in protectRoute middleware: ",error.message);
        res.status(500).json({msg:"Internal Server Error"});
    }
}
