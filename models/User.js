import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    profileImage: String,
    userName: String,
    firstName: String,
    lastName: String,
    email: { type: String, required: true, unique: true, match: /\S+@\S+\.\S+/ },
    password: { type: String, required: false, minlength: 8 },
    profileType: String,
    selectedInstruments: Array,
    selectedGenres: Array,
    location: String,
    bandMembers: { type: [mongoose.Schema.Types.ObjectId], ref: "User", default: [] },
    bands: { type: [mongoose.Schema.Types.ObjectId], ref: "User", default: [] },
    bio: String,

    // --- PASSKEY FIELDS ---
    passkeyId: { type: String, default: null },
    publicKey: { type: String, default: null },
    passkeyCounter: { type: Number, default: 0 },
    lastPasskeyUsed: { type: Date, default: null },
});

export default mongoose.model("User", userSchema);