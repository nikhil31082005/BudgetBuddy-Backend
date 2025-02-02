import mongoose from 'mongoose';

const reportSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    type: {
        type: String,
        enum: ['monthly', 'yearly', 'custom'],
        required: true,
    },
    startDate: {
        type: Date,
        required: true,
    }, 
    endDate: {
        type: Date,
        required: true,
    },
    totalIncome: {
        type: Number,
        default: 0,
    },
    totalExpense: {
        type: Number,
        default: 0,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

const Report = mongoose.model('Report', reportSchema);
export default Report;
