import express from "express";
import base64url from "base64url";
import User from "../models/User.js";
import { Buffer } from "buffer";
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from "@simplewebauthn/server";

const router = express.Router();

// In-memory challenge store for demo (use DB/session in production)
const challengeStore = new Map();

// -----------------------------
// 1️⃣ Generate Passkey Registration Challenge
// -----------------------------
router.post("/passkey-challenge", async (req, res) => {
    try {
        const { userId } = req.body;

        if (!userId) return res.status(400).json({ error: "Missing userId" });

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        // Convert Mongo ObjectId to Buffer for v13
        const userIdString = user._id.toString();
        const userIdBuffer = Buffer.from(userIdString, 'utf8');

        // v13 API format - userID must be Buffer, not string
        const options = await generateRegistrationOptions({
            rpName: "Riffn",
            rpID: "localhost", // replace with your domain in production
            userID: userIdBuffer, // Use Buffer directly
            userName: user.userName || user.email || `${user.firstName}${user.lastName}`,
            userDisplayName: `${user.firstName} ${user.lastName}`,
            attestationType: "none",
            authenticatorSelection: {
                userVerification: "preferred",
                residentKey: "preferred"
            },
            supportedAlgorithmIDs: [-7, -257], // ES256 and RS256
            timeout: 60000,
        });

        // Save challenge for verification
        challengeStore.set(userId, options.challenge);

        res.json(options);
    } catch (err) {
        console.error("Passkey challenge error:", err);
        res.status(500).json({
            error: "Failed to generate passkey challenge",
            details: err.message
        });
    }
});

// -----------------------------
// 2️⃣ Verify Passkey Registration
// -----------------------------
router.post("/users/:userId/passkeys", async (req, res) => {
    const { userId } = req.params;
    const { attestationResponse } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        const expectedChallenge = challengeStore.get(userId);
        if (!expectedChallenge) {
            return res.status(400).json({ error: "No challenge found for this user" });
        }

        const verification = await verifyRegistrationResponse({
            response: attestationResponse,
            expectedChallenge,
            expectedOrigin: ["http://localhost:3000", "http://localhost:5173"],
            expectedRPID: "localhost", // Should match rpID from registration
        });

        if (!verification.verified) {
            return res.status(400).json({ error: "Passkey registration failed" });
        }

        // In v13, the credential data is nested under registrationInfo.credential
        const credential = verification.registrationInfo?.credential;
        if (!credential) {
            throw new Error("No credential found in verification result");
        }

        const { id: credentialID, publicKey: credentialPublicKey, counter } = credential;

        // Save the passkey data
        user.passkeyId = base64url.encode(credentialID);
        user.publicKey = base64url.encode(credentialPublicKey);
        user.passkeyCounter = counter || 0;
        await user.save();

        // Clean up the challenge
        challengeStore.delete(userId);

        res.json({ success: true });
    } catch (err) {
        console.error("Passkey registration verification error:", err);
        res.status(500).json({
            error: "Passkey registration verification failed",
            details: err.message
        });
    }
});

// -----------------------------
// 3️⃣ Generate Passkey Login Challenge
// -----------------------------
router.post("/users/passkey-login-challenge", async (req, res) => {
    try {
        const { email } = req.body;
        console.log("Login challenge for email:", email);

        const user = await User.findOne({ email });
        if (!user || !user.passkeyId) {
            return res.status(404).json({ error: "User or passkey not found" });
        }

        const options = await generateAuthenticationOptions({
            allowCredentials: [
                {
                    id: base64url.toBuffer(user.passkeyId),
                    type: "public-key",
                },
            ],
            userVerification: "preferred",
            rpID: "localhost",
        });

        challengeStore.set(user._id.toString(), options.challenge);

        console.log("Generated login challenge");

        res.json({ options, userId: user._id });
    } catch (err) {
        console.error("Login challenge error:", err);
        res.status(500).json({
            error: "Failed to generate login challenge",
            details: err.message
        });
    }
});

// -----------------------------
// 4️⃣ Verify Passkey Login
// -----------------------------
router.post("/users/passkey-login", async (req, res) => {
    try {
        const { userId, assertionResponse } = req.body;
        console.log("Login verification for userId:", userId);

        const user = await User.findById(userId);
        if (!user || !user.passkeyId) {
            return res.status(404).json({ error: "User or passkey not found" });
        }

        const expectedChallenge = challengeStore.get(userId);
        if (!expectedChallenge) {
            return res.status(400).json({ error: "No challenge found for login" });
        }

        const verification = await verifyAuthenticationResponse({
            response: assertionResponse,
            expectedChallenge,
            expectedOrigin: ["http://localhost:3000", "http://localhost:5173"],
            expectedRPID: "localhost",
            authenticator: {
                credentialID: base64url.toBuffer(user.passkeyId),
                credentialPublicKey: base64url.toBuffer(user.publicKey),
                counter: user.passkeyCounter || 0,
            },
        });

        if (!verification.verified) {
            return res.status(401).json({ error: "Passkey login failed" });
        }

        // Update counter
        user.passkeyCounter = verification.authenticationInfo.newCounter;
        user.lastPasskeyUsed = new Date();
        await user.save();

        challengeStore.delete(userId);

        console.log("Passkey login successful");

        res.json({ user });
    } catch (err) {
        console.error("Login verification error:", err);
        res.status(500).json({
            error: "Passkey login verification failed",
            details: err.message
        });
    }
});

export default router;