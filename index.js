import express from 'express';
import cors from 'cors';
import authRoute from './Routes/auth.js';
import profileRoute from './Routes/profile.js';
import transactionRoute from './Routes/transaction.js'
import budgetRoute from './Routes/budget.js';
import goalRoute from './Routes/goal.js';
import connectMongoDB from './Database/connectToMongoDB.js';
import cookieParser from 'cookie-parser';
// import { authenticateJWT } fro m './Middleware/protectedRoute.js';
import dotenv from 'dotenv';
import cloudinary from './cloudinaryConfig.js';
import multer from 'multer';

const storage = multer.memoryStorage();
// const upload = multer({ storage });


dotenv.config();

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET
});




const app = express();

const corsOptions = {
    origin: process.env.CORS_URL,
    credentials: true,
};
app.use(cors(corsOptions));


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use('/auth', authRoute);
app.use('/user', profileRoute);
app.use('/transaction', transactionRoute)
app.use('/budget',budgetRoute)
app.use('/goal', goalRoute);

app.get('/', (req, res) => {
  res.send("Hello world");
})

const PORT = process.env.PORT;
app.listen(PORT, '0.0.0.0', () => {
    console.log('Server is running on port 8000.');
    connectMongoDB();
});
