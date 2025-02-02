import express from 'express';
import { editProfile, profile } from '../Controllers/profile.controller.js';
import { authenticateJWT } from '../Middleware/protectedRoute.js';

import multer from 'multer';

const Router = express.Router();

const storage = multer.memoryStorage();
const upload = multer({ storage });

Router.get('/profile', authenticateJWT, profile);
Router.post('/edit-profile', authenticateJWT , upload.single('image'), editProfile);


export default Router; 