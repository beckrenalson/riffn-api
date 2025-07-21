import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import multer from 'multer';
import bcrypt from 'bcrypt'
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import { body, validationResult } from 'express-validator'

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

// Users
router.get('/users', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

router.post('/users',
    [
        body('email')
            .isEmail().withMessage('Invalid email address')
            .normalizeEmail(),
        body('password')
            .isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
        body('username')
            .trim().notEmpty().withMessage('Username is required'),
        body('profileImage')
            .optional().isURL().withMessage('Profile image must be a valid URL'),
        body('genres')
            .isArray({ min: 1 }).withMessage('At least one genre must be selected'),
        body('instruments')
            .isArray({ min: 1 }).withMessage('At least one instrument must be selected'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { password, profileImage } = req.body;
            const hashedPassword = await bcrypt.hash(password, 10);

            const user = new User({
                ...req.body,
                password: hashedPassword,
                profileImage: profileImage || null,
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

router.post("/users/check-details",
    [
        body("email")
            .isEmail()
            .withMessage("Invalid email address")
            .normalizeEmail(),
        body("firstName")
            .trim()
            .notEmpty()
            .withMessage("First name is required"),
        body("lastName")
            .trim()
            .notEmpty()
            .withMessage("Last name is required"),
        body("password")
            .isLength({ min: 8 })
            .withMessage("Password must be at least 8 characters long"),
    ],
    async (req, res) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email } = req.body;

        try {
            const user = await User.findOne({ email });

            if (user) {
                return res.status(409).json({
                    errors: [{ param: "email", msg: "Email already in use" }],
                });
            }

            return res.status(200).json({ available: true });
        } catch (err) {
            console.error("Error checking email:", err);
            return res.status(500).json({ error: "Server error" });
        }
    });

router.delete('/users/:id', async (req, res) => {
    try {
        const deletedUser = await User.findByIdAndDelete(req.params.id);

        if (!deletedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Optionally, delete related resources here

        res.json({ message: 'User account deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Server error' });
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
