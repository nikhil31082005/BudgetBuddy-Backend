import User from '../Models/user.model.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();  // Ensure environment variables are loaded

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Signup Controller
export const signup = async (req, res) => {
    try {
        const { name, email, password, jobType } = req.body;

        const existUser = await User.findOne({ email });
        if (existUser) {
            return res.status(400).json({ error: 'Email is already taken' });
        }

        // Password Validation
        function isStrongPassword(password) {
            const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/;
            const minLength = 8;

            if (password.length < minLength) {
                return { isValid: false, message: 'Password must be at least 8 characters long.' };
            }
            if (!passwordRegex.test(password)) {
                return {
                    isValid: false,
                    message: 'Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character.',
                };
            }
            return { isValid: true, message: 'Password is strong.' };
        }

        const result = isStrongPassword(password);
        if (!result.isValid) {
            return res.status(400).json({ error: result.message });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const newUser = new User({ name, email, password: hashedPassword, jobType, createdAt: new Date().toISOString(), profileImage: "https://via.placeholder.com/100" });
        await newUser.save();

        // Generate JWT
        const token = jwt.sign({ id: newUser._id }, JWT_SECRET, { expiresIn: '1h' });
        console.log(token);

        // Set token in HTTP-only cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: false, // Set to false for localhost (no HTTPS)
            sameSite: "lax", // Set this to "lax" or "strict"
            maxAge: 60 * 60 * 1000, // 1 hour
        });
        

        res.status(201).json({ token, message: 'User registered successfully', user: newUser });
    } catch (error) {
        console.error('Error in signup controller', error);
        res.status(500).json({ error });
    }
};

// Login Controller
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Email not found' });
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(400).json({ error: 'Password is incorrect' });
        }

        // Generate JWT
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
        // console.log(token);


        // Set token in HTTP-only cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: false, // Set to false for localhost (no HTTPS)
            sameSite: "lax", // Set this to "lax" or "strict"
            maxAge: 60 * 60 * 1000, // 1 hour
        });
        

        res.status(200).json({ token, message: 'Login successful', user: user });
    } catch (error) {
        console.error('Error during login', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};


export const logout = (req, res) => {
    // Clear the 'token' cookie
    res.clearCookie("token", {
        httpOnly: true,
        secure: false,  // Set to true in production with HTTPS
        sameSite: "lax"
    });
    res.status(200).json({ message: "Logout successful" });
};




export const getMe = async (req, res) => {
    try {
        const user = req.user;  // `req.user` should be set by the middleware

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        
        // Return user data excluding sensitive info (like password)
        const userData = {
            _id: user._id,
            name: user.name,
            email: user.email,
            jobType: user.jobType,
            profileImage: user.profileImage
        };

        res.status(200).json(userData);
    } catch (error) {
        console.error("Error in getMe controller", error.message);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

