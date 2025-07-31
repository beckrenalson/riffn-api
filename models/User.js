import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    profileImage: String,
    userName: String,
    firstName: String,
    lastName: String,
    email: {
        type: String,
        required: true,
        unique: true,
        match: /\S+@\S+\.\S+/
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    },
    profileType: String,
    selectedInstruments: Array,
    selectedGenres: Array,
    location: String,
    bandMembers: Array,
    bio: String,
    credentials: [
        {
            credentialID: Buffer,
            publicKey: Buffer,
            counter: Number,
        },

    ],
});

export default mongoose.model('User', userSchema);
