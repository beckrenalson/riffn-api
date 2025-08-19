import express from 'express';
import Instrument from '../models/Instrument.js';

const router = express.Router();

// Get all instruments
router.get('/', async (req, res) => {
    try {
        const instruments = await Instrument.find();
        res.json(instruments);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get instruments by type
router.get('/:type', async (req, res) => {
    try {
        const { type } = req.params;
        const query = await Instrument.find({ type });
        res.json(query);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

export default router;