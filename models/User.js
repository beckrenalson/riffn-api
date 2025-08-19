import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    profileImage: String,
    userName: String,
    firstName: String,
    lastName: String,
    email: { type: String, required: true, unique: true, match: /\S+@\S+\.\S+/ },
    password: { type: String, require: true, minlength: 8 },
    profileType: String,
    selectedInstruments: Array,
    selectedGenres: Array,
    location: String,
    bandMembers: { type: [mongoose.Schema.Types.ObjectId], ref: 'User', default: [] },
    bands: { type: [mongoose.Schema.Types.ObjectId], ref: 'User', default: [] },
    bio: String
});

export default mongoose.model('User', userSchema);