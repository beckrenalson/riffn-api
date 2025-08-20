import express from 'express';
import bcrypt from 'bcrypt';
import { body, validationResult } from 'express-validator';
import User from '../models/User.js';

const router = express.Router();

const populateOptions = [
    { path: 'bandMembers', select: 'userName firstName lastName profileImage' },
    { path: 'bands', select: 'userName profileImage' },
];

const cleanUser = (user) => {
    if (!user) return null;
    const obj = user.toObject();
    obj.bandMembers = (obj.bandMembers || []).filter(Boolean);
    obj.bands = (obj.bands || []).filter(Boolean);
    return obj;
};

// --------------------------------------------
// Get all users (with optional search)
// --------------------------------------------
router.get('/', async (req, res) => {
    try {
        const search = req.query.search || '';
        let query = {};
        if (search) {
            query.userName = { $regex: search, $options: 'i' };
        }

        const users = await User.find(query)
            .populate(populateOptions)
            .select('-password');

        res.json(users.map(cleanUser));
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --------------------------------------------
// Get user by username (must come before :id)
// --------------------------------------------
router.get('/username/:userName', async (req, res) => {
    try {
        const user = await User.findOne({ userName: req.params.userName })
            .populate(populateOptions)
            .select('-password');

        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(cleanUser(user));
    } catch (err) {
        console.error('Error fetching user by username:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --------------------------------------------
// Get single user by ID
// --------------------------------------------
router.get('/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .populate(populateOptions)
            .select('-password');

        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(cleanUser(user));
    } catch (err) {
        console.error('Error fetching user:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --------------------------------------------
// Create user
// --------------------------------------------
router.post(
    '/',
    [
        body('userName').notEmpty().withMessage('Username required'),
        body('email').isEmail().withMessage('Valid email required'),
        body('password').isLength({ min: 6 }).withMessage('Password min 6 chars'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty())
            return res.status(400).json({ errors: errors.array() });

        try {
            const { userName, email, password, ...rest } = req.body;

            const existing = await User.findOne({ $or: [{ email }, { userName }] });
            if (existing)
                return res.status(400).json({ error: 'Email or username already taken' });

            const hashedPassword = await bcrypt.hash(password, 10);

            const user = new User({
                userName,
                email,
                password: hashedPassword,
                ...rest,
            });

            const savedUser = await user.save();
            await savedUser.populate(populateOptions);

            res.status(201).json(cleanUser(savedUser));
        } catch (err) {
            console.error('Error creating user:', err);
            res.status(500).json({ error: 'Server error' });
        }
    }
);

// --------------------------------------------
// Update user (PATCH)
// --------------------------------------------
router.patch('/:id', async (req, res) => {
    try {
        const allowed = [
            'userName',
            'firstName',
            'lastName',
            'email',
            'profileImage',
            'bandMembers',
            'bands',
        ];
        const updateData = {};
        for (const key of allowed) {
            if (req.body[key] !== undefined) updateData[key] = req.body[key];
        }

        const updated = await User.findByIdAndUpdate(req.params.id, updateData, {
            new: true,
        })
            .populate(populateOptions)
            .select('-password');

        if (!updated) return res.status(404).json({ error: 'User not found' });
        res.json(cleanUser(updated));
    } catch (err) {
        console.error('Error updating user:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --------------------------------------------
// Delete user
// --------------------------------------------
router.delete('/:id', async (req, res) => {
    try {
        const deleted = await User.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ error: 'User not found' });
        res.json({ message: 'User deleted' });
    } catch (err) {
        console.error('Error deleting user:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --------------------------------------------
// Band member management
// --------------------------------------------
router.post('/:id/bandMembers', async (req, res) => {
    try {
        const { memberId } = req.body;
        const updated = await User.findByIdAndUpdate(
            req.params.id,
            { $addToSet: { bandMembers: memberId } },
            { new: true }
        )
            .populate(populateOptions)
            .select('-password');

        if (!updated) return res.status(404).json({ error: 'User not found' });
        res.json(cleanUser(updated));
    } catch (err) {
        console.error('Error adding band member:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

router.delete('/:id/bandMembers/:memberId', async (req, res) => {
    try {
        const updated = await User.findByIdAndUpdate(
            req.params.id,
            { $pull: { bandMembers: req.params.memberId } },
            { new: true }
        )
            .populate(populateOptions)
            .select('-password');

        if (!updated) return res.status(404).json({ error: 'User not found' });
        res.json(cleanUser(updated));
    } catch (err) {
        console.error('Error removing band member:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

export default router;
