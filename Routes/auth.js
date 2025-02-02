import express from 'express';
import { getMe, login, logout, signup } from '../Controllers/auth.controller.js';
import { authenticateJWT } from '../Middleware/protectedRoute.js';

const Router = express.Router();

Router.get('/me', authenticateJWT, getMe);
Router.post('/signup', signup);
Router.post('/login', login);
Router.post('/logout', logout) 

export default Router;
