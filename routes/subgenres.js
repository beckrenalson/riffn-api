import express from 'express';
import SubGenre from '../models/SubGenre.js';

const router = express.Router();

// Get all subgenres
router.get('/', async (req, res) => {
    try {
        const subgenres = await SubGenre.find();
        res.json(subgenres);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get subgenres by genre
router.get('/:genre', async (req, res) => {
    try {
        const { genre } = req.params;
        const query = await SubGenre.find({ genre });
        res.json(query);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

export default router;