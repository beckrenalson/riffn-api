import express from 'express';
import multer from 'multer';
import path from 'path';
import bcrypt from 'bcrypt'

import User from '../models/User.js';
import Instrument from '../models/Instrument.js';
import SubGenre from '../models/SubGenre.js';

const router = express.Router();

// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`;
        cb(null, uniqueName);
    }
});

const upload = multer({ storage });

// SubGenres
router.get('/subgenres', async (req, res) => {
    try {
        const subgenres = await SubGenre.find();
        res.json(subgenres);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

router.get('/subgenres/:genre', async (req, res) => {
    try {
        const { genre } = req.params;
        const query = await SubGenre.find({ genre });
        res.json(query);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

router.post('/subgenres', async (req, res) => {
    try {
        const subgenre = new SubGenre(req.body);
        await subgenre.save();
        res.json(subgenre);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

// Instruments
router.get('/instruments', async (req, res) => {
    try {
        const instruments = await Instrument.find();
        res.json(instruments);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

router.get('/instruments/:type', async (req, res) => {
    try {
        const { type } = req.params;
        const query = await Instrument.find({ type });
        res.json(query);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

router.post('/instruments', async (req, res) => {
    try {
        const instrument = new Instrument(req.body);
        await instrument.save();
        res.json(instrument);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

// Users
router.get('/users', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

router.post('/users', upload.single('profileImage'), async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)

        const user = new User({
            ...req.body,
            password: hashedPassword,
            profileImage: req.file?.path || null
        });

        await user.save();
        res.json(user);
    } catch (error) {
        console.error('Error saving user:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

router.patch('/users/:id', async (req, res) => {
    try {
        const updateData = { ...req.body };

        if (updateData.password) {
            updateData.password = await bcrypt.hash(updateData.password, 10);
        }

        const updated = await User.findByIdAndUpdate(req.params.id, updateData, { new: true });

        if (!updated) return res.status(404).json({ error: 'User not found' });

        res.json(updated);
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

export default router;
