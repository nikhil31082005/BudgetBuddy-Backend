import express from 'express';
import { authenticateJWT } from '../Middleware/protectedRoute.js';
import { addBudget, deleteBudget, getBudget } from '../Controllers/budget.controller.js';

const Router = express.Router();

Router.post('/addBudget', authenticateJWT, addBudget);
Router.get('/:userId',authenticateJWT, getBudget);
// Router.put('/updateBudget/:id', authenticateJWT, updateBudget);
Router.delete('/deleteBudget/:id', authenticateJWT, deleteBudget);


export default Router; 