import mongoose from 'mongoose';

const connectionRequestSchema = new mongoose.Schema({
    fromUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    toBand: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    toSolo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, default: 'pending' } // pending, accepted, rejected
}, { timestamps: true });

export default mongoose.model('ConnectionRequest', connectionRequestSchema);
