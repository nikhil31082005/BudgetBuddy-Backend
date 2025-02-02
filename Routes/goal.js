import express from 'express';
import { authenticateJWT } from '../Middleware/protectedRoute.js';
import { addGoal, getGoals, updataGoals } from '../Controllers/goal.controller.js';

const Router = express.Router();

Router.post('/addGoal', authenticateJWT, addGoal);
Router.get('/:userId', authenticateJWT, getGoals);
Router.put('/update/:goalId', authenticateJWT, updataGoals);


export default Router;
 