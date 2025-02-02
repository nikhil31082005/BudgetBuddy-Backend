import Goal from '../Models/goal.model.js';

export const addGoal = async (req, res) => {
    const userId = req.user._id;

    try {
        const { name, targetAmount, currentAmount = 0, deadline, description } = req.body;

        let status = 'in-progress'; // Default status
        const now = new Date();

        if (currentAmount >= targetAmount) {
            status = 'completed';
        } else if (new Date(deadline) < now) {
            status = 'failed';
        }

        const newGoal = new Goal({ 
            user: userId, 
            name, 
            targetAmount, 
            currentAmount, 
            deadline, 
            description, 
            status 
        });
        const saveGoal = await newGoal.save();
        return res.status(201).json({ message: 'Goal created successfully', Goal: saveGoal });
    } catch (error) {
        console.error("Error creating goal:", error.message); // Log the error
        return res.status(500).json({ error: 'Failed to create goal', details: error.message });
    }
}

export const getGoals = async (req, res) => {
    const { userId } = req.params;
    try {
        const allGoals = await Goal.find({ user: userId });
        return res.status(200).json({ message: 'Goals fetched successfully', goals: allGoals });
    } catch (error) {
        console.error('Error fetching goals:', error.message);
        return res.status(500).json({ error: "Internal Server Error", details: error.message });
    }
};

export const updataGoals = async (req, res) => {
    const { goalId } = req.params;
    const { currentAmount } =  req.body;
    try {
        const updatedGoal = await Goal.findByIdAndUpdate(goalId, {currentAmount});
        return res.status(200).json({message: 'Amount updated successfully', goal: updatedGoal});
    } 
    catch (error) {
        res.status(500).json({ error: 'Error updating goal', details: error.message });
    }
}
