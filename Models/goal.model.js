import mongoose from 'mongoose';

const goalSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    name: {
        type: String,
        required: true,
        trim: true,
    },
    targetAmount: { 
        type: Number,
        required: true,
    },
    currentAmount: {
        type: Number,
        default: 0,
    },
    deadline: {
        type: Date,
        required: true,
    },
    description: {
        type: String,
    },
    status: {
        type: String,
        enum: ['in-progress', 'completed', 'failed'],
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

const Goal = mongoose.model('Goal', goalSchema);
export default Goal;
