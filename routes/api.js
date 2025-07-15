import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import multer from 'multer';
import bcrypt from 'bcrypt'
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';

import User from '../models/User.js';
import Instrument from '../models/Instrument.js';
import SubGenre from '../models/SubGenre.js';

const router = express.Router();

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
    cloudinary,
    params: {
        folder: 'riffn-profile-images', // optional folder in Cloudinary
        allowed_formats: ['jpg', 'png', 'jpeg'],
        transformation: [{ width: 800, height: 800, crop: 'limit' }],
    },
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

router.post('/users', async (req, res) => {
    try {
        const { password, profileImage } = req.body;

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            ...req.body,
            password: hashedPassword,
            profileImage: profileImage || null
        });

        await user.save();
        res.status(201).json(user);
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

router.post('/users/check-email', async (req, res) => {
    const { email } = req.body;

    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = await User.findOne({ email });

    if (user) {
        return res.status(409).json({ error: 'Email already in use' });
    } else {
        return res.status(200).json({ available: true });
    }
});

router.post('/uploads', upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    res.json({
        url: req.file.path, // Cloudinary's public URL
    });
});

export default router;
