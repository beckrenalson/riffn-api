// ===== REFACTORED users.js =====
import dotenv from 'dotenv'
import express from "express";
import bcrypt from "bcrypt";
import { body, validationResult } from "express-validator";
import User from "../models/User.js";
import ConnectionRequest from '../models/ConnectionRequest.js'; // Import ConnectionRequest model
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import challengeStore from "../utils/challengeStore.js";

dotenv.config()

const router = express.Router();

const expectedOrigin = [process.env.PASSKEY_ORIGIN];
const expectedRPID = process.env.PASSKEY_RPID;

// --- Cleanup expired challenges every minute ---
const cleanupExpiredChallenges = () => {
    const now = Date.now();
    const maxAge = 15 * 60 * 1000; // 15 minutes

    for (const [key, value] of challengeStore.entries()) {
        if (value.timestamp && now - value.timestamp > maxAge) {
            console.log("🧹 Cleaning up expired challenge:", key);
            challengeStore.delete(key);
        }
    }
};
setInterval(cleanupExpiredChallenges, 60000);

// --- Populate options for users ---
const populateOptions = [
    { path: "bandMembers", select: "userName firstName lastName profileImage selectedInstruments selectedGenres email phone socials bio location" },
    { path: "bands", select: "userName profileImage" },
];

// --- Helpers ---
const cleanUser = (user) => {
    if (!user) return null;
    const obj = user.toObject();
    obj.bandMembers = (obj.bandMembers || []).filter(Boolean);
    obj.bands = (obj.bands || []).filter(Boolean);
    return obj;
};

const handleValidation = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    next();
};

const asyncHandler = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

// --- Validation rules ---
const userValidation = [
    body("firstName").trim().notEmpty().withMessage("First name required"),
    body("lastName").trim().notEmpty().withMessage("Last name required"),
    body("email").isEmail().withMessage("Valid email required").normalizeEmail(),
    body("password").isLength({ min: 8 }).withMessage("Password must be at least 8 characters long"),
];

// --- Routes ---

// GET all users with optional search
router.get(
    "/",
    asyncHandler(async (req, res) => {
        const search = req.query.search || "";
        const query = search ? { userName: { $regex: search, $options: "i" } } : {};
        const users = await User.find(query).populate(populateOptions).select("-password");
        res.json(users.map(cleanUser));
    })
);

// POST check if email is available
router.post(
    "/check-details",
    [
        body("email").isEmail().withMessage("Invalid email").normalizeEmail(),
        body("firstName").trim().notEmpty().withMessage("First name required"),
        body("lastName").trim().notEmpty().withMessage("Last name required"),
        body("password").isLength({ min: 8 }).withMessage("Password must be at least 8 characters long"),
    ],
    handleValidation,
    asyncHandler(async (req, res) => {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (user) return res.status(409).json({ errors: [{ msg: "Email already in use", param: "email" }] });
        res.json({ available: true });
    })
);

// GET user by username
router.get(
    "/username/:userName",
    asyncHandler(async (req, res) => {
        const user = await User.findOne({ userName: req.params.userName }).populate(populateOptions).select("-password");
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(cleanUser(user));
    })
);

// GET user by ID
router.get(
    "/:id",
    asyncHandler(async (req, res) => {
        const user = await User.findById(req.params.id).populate(populateOptions).select("-password");
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(cleanUser(user));
    })
);

// POST create user with optional passkey
router.post(
    "/",
    userValidation,
    handleValidation,
    asyncHandler(async (req, res) => {
        const { firstName, lastName, email, password, userName, passkeyData, ...rest } = req.body;

        // Cleanup expired challenges
        cleanupExpiredChallenges();

        // Check if user already exists
        const existingUser = await User.findOne({
            $or: [
                { email },
                { userName: userName || `${firstName}${lastName}`.toLowerCase() },
            ],
        });
        if (existingUser)
            return res.status(409).json({ errors: [{ msg: "Email or username already in use" }] });

        // Create new user
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            userName: userName || `${firstName}${lastName}`.toLowerCase(),
            ...rest,
        });

        // --- Passkey registration ---
        if (passkeyData?.tempUserId && passkeyData.credential) {
            const challengeData = challengeStore.get(passkeyData.tempUserId);

            if (challengeData) {
                try {
                    const verification = await verifyRegistrationResponse({
                        response: passkeyData.credential,
                        expectedChallenge: challengeData.challenge,
                        expectedOrigin,
                        expectedRPID,
                    });

                    if (verification.verified && verification.registrationInfo?.credential) {
                        const credential = verification.registrationInfo.credential;

                        // Convert ArrayBuffers to Node Buffers before encoding
                        user.passkeyId = isoBase64URL.fromBuffer(Buffer.from(credential.id));
                        user.publicKey = isoBase64URL.fromBuffer(Buffer.from(credential.publicKey));
                        user.passkeyCounter = credential.counter || 0;
                        user.hasPasskey = true;

                        console.log("✅ Passkey successfully registered:", user.passkeyId);
                    } else {
                        console.warn("❌ Passkey verification failed or no credential returned");
                    }
                } catch (err) {
                    console.error("❌ Passkey registration error:", err);
                }

                // Remove challenge after processing
                challengeStore.delete(passkeyData.tempUserId);
            } else {
                console.warn(`❌ No challenge found for tempUserId: ${passkeyData.tempUserId}`);
            }
        }

        // Save user to DB
        await user.save();
        await user.populate(populateOptions);

        const userResponse = cleanUser(user);
        userResponse.hasPasskey = !!user.passkeyId;

        res.status(201).json(userResponse);
    })
);


// PATCH update user
router.patch(
    "/:id",
    asyncHandler(async (req, res) => {
        const allowed = ["firstName", "lastName", "profileImage", "bandMembers", "bands", "selectedInstruments", "selectedGenres", "email", "location", "bio", "musicEmbedUrl"];
        const updateData = {};
        for (const key of allowed) if (req.body[key] !== undefined) updateData[key] = req.body[key];

        const updated = await User.findByIdAndUpdate(req.params.id, updateData, { new: true }).populate(populateOptions).select("-password");
        if (!updated) return res.status(404).json({ error: "User not found" });
        res.json(cleanUser(updated));
    })
);

// DELETE user
router.delete("/:id", asyncHandler(async (req, res) => {
    const deleted = await User.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "User not found" });
    res.json({ message: "User deleted" });
}));

// ADD band member
router.post("/:id/bandMembers", asyncHandler(async (req, res) => {
    const { memberId } = req.body;
    const member = await User.findById(memberId);
    if (!member) return res.status(404).json({ error: "Member not found" });

    const updated = await User.findByIdAndUpdate(req.params.id, { $addToSet: { bandMembers: memberId } }, { new: true })
        .populate(populateOptions)
        .select("-password");

    if (!updated) return res.status(404).json({ error: "User not found" });
    res.json(cleanUser(updated));
}));

// REMOVE band member
router.delete("/:id/bandMembers/:memberId", asyncHandler(async (req, res) => {
    const updated = await User.findByIdAndUpdate(req.params.id, { $pull: { bandMembers: req.params.memberId } }, { new: true })
        .populate(populateOptions)
        .select("-password");

    if (!updated) return res.status(404).json({ error: "User not found" });

    console.log("Band ID:", req.params.id);
    console.log("Member ID:", req.params.memberId);

    const deleteQuery = {
        $or: [
            // Case 1: Member sent request to band
            { fromUser: req.params.memberId, toBand: req.params.id },
            // Case 2: Band sent request to solo member
            { fromUser: req.params.id, toSolo: req.params.memberId },
            // Case 3: Band sent request to another band (which is now the member)
            { fromUser: req.params.id, toBand: req.params.memberId }
        ]
    };

    console.log("Delete Query:", JSON.stringify(deleteQuery));

    // Delete all connection requests involving both the band (req.params.id)
    // and the removed member (req.params.memberId), regardless of status.
    await ConnectionRequest.deleteMany(deleteQuery);

    res.json(cleanUser(updated));
}));

// CENTRAL ERROR HANDLER
router.use((err, req, res, next) => {
    console.error(err.stack || err);
    res.status(500).json({ error: "Server error" });
});

export default router;
