import User from "../Models/user.model.js";
import Transaction from "../Models/transaction.model.js";

export const addIncome = async (req, res) => {
    try {

        const userId = req.user.id;

        // Extract data from the request body
        const { amount , category, paymentMethod, date, time, description } = req.body;

        // Validate required fields
        if (!amount || !paymentMethod || !date || !time) {
            return res.status(400).json({ error: 'All required fields must be provided' });
        }

        // Create a new transaction of type "income"
        const newTransaction = new Transaction({
            user: userId,
            class: "income",
            category: category,
            paymentMethod,
            amount,
            date,
            time,
            description,
        });

        // Save the record to the database
        await newTransaction.save();

        return res.status(201).json({ message: 'Income added successfully', transaction: newTransaction });
    } catch (error) {
        // console.error('Error adding income:', error.message);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}

export const addExpence = async (req, res) => {
    try {

        const userId = req.user.id;

        // Extract data from the request body
        const { amount, category, paymentMethod, date, time, description } = req.body;

        // Validate required fields
        if (!amount || !paymentMethod || !date || !time) {
            return res.status(400).json({ error: 'All required fields must be provided' });
        }

        // Create a new transaction of type "income"
        const newTransaction = new Transaction({
            user: userId,
            class: 'expense',
            category: category,
            paymentMethod,
            amount,
            date,
            time,
            description,
        });

        // Save the record to the database
        await newTransaction.save();

        return res.status(201).json({ message: 'Expense added successfully', transaction: newTransaction });
    } catch (error) {
        // console.error('Error adding expense:', error.message);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}

export const getTransaction = async (req, res) => {
    try {
        const userId = req.user.id;

        const transactions = await Transaction.find({ user: userId });
        res.status(200).json({ transactions });
    } catch (error) {
        return res.status(500).json({ error: "Internal Server Error"});
    }
}