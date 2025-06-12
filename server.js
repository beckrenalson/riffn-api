import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors'
import dotenv from 'dotenv';
import multer from 'multer';

dotenv.config(); // Load environment variables

// Connect to MongoDB Atlas

mongoose.connect(process.env.MONGODB_URI);

import path from 'path';

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ storage });

const app = express();
app.use('/uploads', express.static('uploads'));
app.use(express.json());
app.use(cors());

const subGenreSchema = new mongoose.Schema({
  name: String,
  genre: String
});

const SubGenre = mongoose.model('SubGenre', subGenreSchema);

const instrumentSchema = new mongoose.Schema({
  name: String,
  icon: String,
  type: String
})

const Instrument = mongoose.model('Instrument', instrumentSchema)

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
  openings: {
    instruments: Array,
    genres: Array
  },
  bandMembers: Array
})

const User = mongoose.model('User', userSchema)

// API Endpoints

app.get('/subgenres', async (req, res) => {
  try {
    const subgenres = await SubGenre.find();
    res.json(subgenres);
  } catch (error) {
    res.status(500).json({ error: 'Server error' })
  }
});

app.get('/subgenres/:genre', async (req, res) => {
  try {
    const { genre } = req.params
    const query = await SubGenre.find({ genre });
    res.json(query);
  } catch (error) {
    res.status(500).json({ error: 'Server error' })
  }
});

app.post('/subgenres', async (req, res) => {
  try {
    const subgenres = new SubGenre(req.body);
    await subgenres.save();
    res.json(subgenres);
  } catch (error) {
    res.status(500).json({ error: 'Server error' })
  }
});

app.get('/instruments', async (req, res) => {
  try {
    const instruments = await Instrument.find();
    res.json(instruments);
  } catch (error) {
    res.status(500).json({ error: 'Server error' })
  }
});

app.get('/instruments/:type', async (req, res) => {
  try {
    const { type } = req.params
    const query = await Instrument.find({ type });
    res.json(query);
  } catch (error) {
    res.status(500).json({ error: 'Server error' })
  }
});

app.post('/instruments', async (req, res) => {
  try {
    const instruments = new Instrument(req.body);
    await instruments.save();
    res.json(instruments);
  } catch (error) {
    res.status(500).json({ error: 'Server error' })
  }
});

app.get('/users', async (req, res) => {
  try {
    const user = await User.find();
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Server error' })
  }
});

app.post('/users', upload.single('profileImage'), async (req, res) => {
  try {
    console.log('Text fields:', req.body);
    console.log('Uploaded file:', req.file);

    const user = new User({
      ...req.body,
      profileImage: req.file?.path || null
    });

    await user.save();
    res.json(user);
  } catch (error) {
    console.error('Error saving user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/users/:id', async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(updatedUser);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});



// app.get('/students/:id', async (req, res) => {
//     const student = await Student.findById(req.params.id);
//     res.json(student);
// });

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log('Server running on ', { PORT });
});
