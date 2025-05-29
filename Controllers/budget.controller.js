import User from "../Models/user.model.js";
import Budget from "../Models/budget.model.js";

export const addBudget = async (req, res) => {
    const {user} = req.body;
    const userId = user._id;
    const { category, amount, startDate, endDate } = req.body;

    console.log(req.body);

    try {
        if (!userId || !category || !amount || !startDate || !endDate) {
            return res.status(400).json({ error: "All fields are required." });
        }

        const newBudget = new Budget({ userId, category, amount, startDate, endDate });
        const savedBudget = await newBudget.save();
        return res.status(201).json({ message: 'Budget created successfully', budget: savedBudget });
    } catch (error) {
        console.error("Error creating budget:", error.message); // Log the error
        return res.status(500).json({ error: 'Failed to create budget', details: error.message });
    }
};


export const getBudget = async (req, res) => {
    try {
        const { userId } = req.params;
        // console.log(userId);
        const Budgets = await Budget.find({userId});
        // console.log(Budgets);
        return res.status(200).json({ Budgets });
    } catch (error) {
        return res.status(500).json({ error: "Internal Server Error"});
    }
}

export const deleteBudget = async (req, res) => {
    const { id } = req.params; // Get the id from request params
    try {
        console.log(id);
        const deletedBudget = await Budget.findByIdAndDelete(id); // Fixed variable name

        if (!deletedBudget) {
            return res.status(404).json({ message: 'Budget not found!' });
        }

        return res.status(200).json({  message: 'Budget deleted successfully', budget: deletedBudget });
    } catch (error) {
        return res.status(500).json({ error: 'Failed to delete budget', details: error.message });
    }
};

// export const updateBudget = async (req, res) => {
//     const { id } = req.params;
//     const userId = req.user._id;
//     const { category, amount, startDate, endDate } = req.body;
//     try {
//         const newBudget = new Budget({ userId, category, amount, startDate, endDate });
//         await Budget.findByIdAndUpdate(id, newBudget);
//         return res.status(200).json({ message: 'Budget updated successfully'});
//     } catch (error) {
//         return res.status(500).json({ error: 'Failed to update budget', details: error.message });
//     }
// }

