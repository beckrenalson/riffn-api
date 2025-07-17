import express from 'express';
import Track from '../models/Track.js';

const router = express.Router();

router.post('/', async (req, res) => {
    try {
        const { userId, type, src } = req.body;

        if (!userId || !type || !src) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        const newTrack = new Track({ userId, type, src });
        const savedTrack = await newTrack.save();

        res.status(201).json(savedTrack);
    } catch (err) {
        console.error("Error saving track:", err);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

router.get("/:userId", async (req, res) => {
    try {
        const tracks = await Track.find({ userId: req.params.userId });
        res.json(tracks);
    } catch (err) {
        res.status(500).json({ error: "Could not fetch tracks" });
    }
});

export default router