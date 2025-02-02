import express from 'express';
import { addExpence, addIncome, getTransaction } from '../Controllers/transaction.controller.js';
import { authenticateJWT } from '../Middleware/protectedRoute.js';

const Router = express.Router();

Router.get('/transactions', authenticateJWT, getTransaction);
// Router.post('/income', authenticateJWT, addIncome);
Router.post('/income', authenticateJWT, addIncome);
Router.post('/expence', authenticateJWT, addExpence);




export default Router; 