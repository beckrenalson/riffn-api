import express from 'express';
import ConnectionRequest from '../models/ConnectionRequest.js';
import User from '../models/User.js';

const router = express.Router();

// Send a connection request (band → solo or solo → band)
router.post('/request', async (req, res) => {
    const { fromUserId, toBandId, toSoloId } = req.body;

    try {
        const fromUser = await User.findById(fromUserId);
        if (!fromUser) return res.status(404).json({ message: "User does not exist" });

        let existing, request;

        if (toBandId) {
            const band = await User.findById(toBandId);
            if (!band || band.profileType !== 'band') return res.status(404).json({ message: "Band does not exist" });

            existing = await ConnectionRequest.findOne({ fromUser: fromUserId, toBand: toBandId });
            if (existing) return res.status(400).json({ message: "Request already exists" });

            request = await ConnectionRequest.create({ fromUser: fromUserId, toBand: toBandId });
        } else if (toSoloId) {
            const solo = await User.findById(toSoloId);
            if (!solo || solo.profileType !== 'solo') return res.status(404).json({ message: "Solo artist does not exist" });

            existing = await ConnectionRequest.findOne({ fromUser: fromUserId, toSolo: toSoloId });
            if (existing) return res.status(400).json({ message: "Request already exists" });

            request = await ConnectionRequest.create({ fromUser: fromUserId, toSolo: toSoloId });
        } else {
            return res.status(400).json({ message: "No valid target specified" });
        }

        res.json(request);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

// Get all pending requests for a user (band or solo)
router.get('/requests/:userId', async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        let requests = [];

        if (user.profileType === 'band') {
            requests = await ConnectionRequest.find({ toBand: user._id, status: 'pending' })
                .populate('fromUser', 'userName profileType socials');
        } else {
            requests = await ConnectionRequest.find({ toSolo: user._id, status: 'pending' })
                .populate('fromUser', 'userName profileType socials');
        }

        res.json(requests);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

// Accept a request
router.post('/:requestId/accept', async (req, res) => {
    try {
        const request = await ConnectionRequest.findById(req.params.requestId);
        if (!request) return res.status(404).json({ message: "Request not found" });

        const fromUser = await User.findById(request.fromUser);
        const toBand = request.toBand ? await User.findById(request.toBand) : null;
        const toSolo = request.toSolo ? await User.findById(request.toSolo) : null;

        if (!fromUser || (toBand === null && toSolo === null)) return res.status(404).json({ message: "User or target no longer exists" });

        // Add users to each other's arrays
        if (toBand) {
            if (!toBand.bandMembers.includes(fromUser._id)) toBand.bandMembers.push(fromUser._id);
            if (!fromUser.bands.includes(toBand._id)) fromUser.bands.push(toBand._id);
            await toBand.save();
        }
        if (toSolo) {
            if (!toSolo.bands) toSolo.bands = [];
            if (!toSolo.bands.includes(fromUser._id)) toSolo.bands.push(fromUser._id); // band joining solo artist
            await toSolo.save();
        }

        await fromUser.save();

        request.status = 'accepted';
        await request.save();

        res.json({ message: "Request accepted", request });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

// Reject a request
router.post('/:requestId/reject', async (req, res) => {
    try {
        const request = await ConnectionRequest.findById(req.params.requestId);
        if (!request) return res.status(404).json({ message: "Request not found" });

        request.status = 'rejected';
        await request.save();

        res.json({ message: "Request rejected", request });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});

export default router;
