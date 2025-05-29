import jwt from 'jsonwebtoken';
import User from '../Models/user.model.js';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

export const authenticateJWT = async (req, res, next) => {
    // console.log(req.cookies); // Good for debugging, remove for production
    const token = req.cookies.token; // No need for 'await' here, req.cookies is synchronous

    if (!token) {
        return res.status(401).json({ message: 'Access Denied: No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET); // Synchronous
        // Using await here is correct as findById is asynchronous
        req.user = await User.findById(decoded.id).select('-password');

        // Important: If the user is not found, it's still an unauthorized access.
        if (!req.user) {
            return res.status(401).json({ message: 'Unauthorized: User not found' });
        }

        next(); // Proceed to the next middleware/route handler
    } catch (error) {
        // Log the error for debugging purposes (in development/staging)
        console.error('JWT Verification Error:', error.message);
        // Different error messages for different jwt errors
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Unauthorized: Token has expired' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({ message: 'Forbidden: Invalid token' });
        }
        return res.status(500).json({ message: 'Internal Server Error during authentication' });
    }
};