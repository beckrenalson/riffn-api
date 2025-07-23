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

router.delete("/:trackId", async (req, res) => {
    try {
        const deleted = await Track.findByIdAndDelete(req.params.trackId);
        if (!deleted) {
            return res.status(404).json({ message: "Track not found" });
        }
        res.status(200).json({ message: "Track deleted" });
    } catch (err) {
        console.error("Error deleting track:", err);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

export default router