import mongoose from "mongoose";

const trackSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    type: { type: String, enum: ["spotify", "soundcloud"], required: true },
    src: { type: String, required: true },
});

const Track = mongoose.model("Track", trackSchema);
export default Track;
