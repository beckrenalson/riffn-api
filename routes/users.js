import express from 'express';
import bcrypt from 'bcrypt';
import { body, validationResult } from 'express-validator';
import User from '../models/User.js';

const router = express.Router();

// Get all users
router.get('/', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

// Create new user
router.post('/',
    [
        body('email')
            .isEmail().withMessage('Invalid email address')
            .normalizeEmail(),
        body('password')
            .isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
        body('userName')
            .trim().notEmpty().withMessage('Username is required'),
        body('selectedGenres')
            .isArray({ min: 1 }).withMessage('At least one genre must be selected'),
        body('selectedInstruments')
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

// Update user
router.patch('/:id', async (req, res) => {
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

// Check user details availability
router.post("/check-details",
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

// Delete user
router.delete('/:id', async (req, res) => {
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

export default router;