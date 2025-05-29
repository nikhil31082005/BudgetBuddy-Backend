import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
        },
        password: {
            type: String,
            required: true,
        },
        profileImage: { 
            type: String  
        },
        jobType: {
            type: String,
            required: true
        },
        createdAt: {
            type: String,
            default: Date.now,
        },
        transactions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }],
        budgets: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Budget' }]

    },
    { timestamps: true }
);

const User = mongoose.model("User", userSchema);

export default User;