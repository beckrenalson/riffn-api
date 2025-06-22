import mongoose from 'mongoose';

const subGenreSchema = new mongoose.Schema({
    name: String,
    genre: String
});

export default mongoose.model('SubGenre', subGenreSchema);
