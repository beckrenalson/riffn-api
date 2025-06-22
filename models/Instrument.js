import mongoose from 'mongoose';

const instrumentSchema = new mongoose.Schema({
    name: String,
    icon: String,
    type: String
});

export default mongoose.model('Instrument', instrumentSchema);
