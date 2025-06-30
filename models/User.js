import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    profileImage: String,
    userName: String,
    firstName: String,
    lastName: String,
    email: String,
    password: String,
    profileType: String,
    selectedInstruments: Array,
    selectedGenres: Array,
    location: String,
    bandMembers: Array,
    bio: String

});

export default mongoose.model('User', userSchema);
