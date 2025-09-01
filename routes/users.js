import dotenv from 'dotenv'
import express from "express";
import bcrypt from "bcrypt";
import { body, validationResult } from "express-validator";
import User from "../models/User.js";
import ConnectionRequest from '../models/ConnectionRequest.js';
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import challengeStore from "../utils/challengeStore.js";
import { updateUserBandArrays } from '../routes/connections.js';

dotenv.config()

const router = express.Router();

const expectedOrigin = [process.env.PASSKEY_ORIGIN];
const expectedRPID = process.env.PASSKEY_RPID;

const cleanupExpiredChallenges = () => {
    const now = Date.now();
    const maxAge = 15 * 60 * 1000;

    for (const [key, value] of challengeStore.entries()) {
        if (value.timestamp && now - value.timestamp > maxAge) {
            challengeStore.delete(key);
        }
    }
};
setInterval(cleanupExpiredChallenges, 60000);

const populateOptions = [
    { path: "bandMembers", select: "userName firstName lastName profileImage selectedInstruments selectedGenres email phone socials bio location" },
    { path: "bands", select: "userName profileImage" },
];

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

const userValidation = [
    body("firstName").trim().notEmpty().withMessage("First name required"),
    body("lastName").trim().notEmpty().withMessage("Last name required"),
    body("email").isEmail().withMessage("Valid email required").normalizeEmail(),
    body("password").isLength({ min: 8 }).withMessage("Password must be at least 8 characters long"),
];

router.get(
    "/",
    asyncHandler(async (req, res) => {
        const search = req.query.search || "";
        const profileType = req.query.profileType || "";
        const query = {};

        if (search) {
            query.userName = { $regex: search, $options: "i" };
        }

        if (profileType === "solo") {
            query.profileType = { $not: { $regex: /^band$/i } };
        }

        const users = await User.find(query).populate(populateOptions).select("-password");
        res.json(users.map(cleanUser));
    })
);

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

router.get(
    "/username/:userName",
    asyncHandler(async (req, res) => {
        const user = await User.findOne({ userName: req.params.userName }).populate(populateOptions).select("-password");
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(cleanUser(user));
    })
);

router.get(
    "/:id",
    asyncHandler(async (req, res) => {
        const user = await User.findById(req.params.id).populate(populateOptions).select("-password");
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(cleanUser(user));
    })
);

router.post(
    "/",
    userValidation,
    handleValidation,
    asyncHandler(async (req, res) => {
        const { firstName, lastName, email, password, userName, passkeyData, ...rest } = req.body;

        cleanupExpiredChallenges();

        const existingUser = await User.findOne({
            $or: [
                { email },
                { userName: userName || `${firstName}${lastName}`.toLowerCase() },
            ],
        });
        if (existingUser)
            return res.status(409).json({ errors: [{ msg: "Email or username already in use" }] });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            userName: userName || `${firstName}${lastName}`.toLowerCase(),
            ...rest,
        });

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

                        user.passkeyId = isoBase64URL.fromBuffer(Buffer.from(credential.id));
                        user.publicKey = isoBase64URL.fromBuffer(Buffer.from(credential.publicKey));
                        user.passkeyCounter = credential.counter || 0;
                        user.hasPasskey = true;
                    }
                } catch (err) {
                    console.error("Passkey registration error:", err);
                }

                challengeStore.delete(passkeyData.tempUserId);
            }
        }

        await user.save();
        await user.populate(populateOptions);

        const userResponse = cleanUser(user);
        userResponse.hasPasskey = !!user.passkeyId;

        res.status(201).json(userResponse);
    })
);

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

router.delete("/:id", asyncHandler(async (req, res) => {
    const deleted = await User.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "User not found" });
    res.json({ message: "User deleted" });
}));

router.post("/:id/bandMembers", asyncHandler(async (req, res) => {
    const { memberId } = req.body;
    const bandId = req.params.id;

    const band = await User.findById(bandId);
    const member = await User.findById(memberId);

    if (!band) return res.status(404).json({ error: "Band not found" });
    if (!member) return res.status(404).json({ error: "Member not found" });

    const existingAcceptedConnection = await ConnectionRequest.findOne({
        fromUser: memberId,
        toBand: bandId,
        status: 'accepted',
    });

    if (existingAcceptedConnection) {
        return res.status(200).json({ message: "User is already an accepted member of this band" });
    }

    await ConnectionRequest.deleteMany({
        fromUser: memberId,
        toBand: bandId,
        status: { $in: ['pending', 'rejected'] },
    });

    const newConnectionRequest = new ConnectionRequest({
        fromUser: memberId,
        toBand: bandId,
        status: 'accepted',
        requestType: 'band_invite',
    });

    await newConnectionRequest.save();

    const fromUser = await User.findById(memberId);
    const toBand = await User.findById(bandId);

    if (fromUser && toBand) {
        await updateUserBandArrays(fromUser, toBand, null);
    } else {
        console.error("Error: Could not find user or band to update arrays after creating accepted connection request.");
    }

    const updatedBand = await User.findById(bandId).populate(populateOptions).select("-password");

    res.status(200).json(cleanUser(updatedBand));
}));

router.delete("/:id/bandMembers/:memberId", asyncHandler(async (req, res) => {
    const updatedBand = await User.findByIdAndUpdate(req.params.id, { $pull: { bandMembers: req.params.memberId } }, { new: true })
        .populate(populateOptions)
        .select("-password");

    if (!updatedBand) return res.status(404).json({ error: "Band not found" });

    await User.findByIdAndUpdate(req.params.memberId, { $pull: { bands: req.params.id } });

    await ConnectionRequest.deleteMany({
        $or: [
            { fromUser: req.params.memberId, toBand: req.params.id },
            { fromUser: req.params.id, toSolo: req.params.memberId },
        ],
    });

    res.json(cleanUser(updatedBand));
}));

router.use((err, req, res, next) => {
    console.error(err.stack || err);
    res.status(500).json({ error: "Server error" });
});

export default router;