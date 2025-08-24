// ===== 2. UPDATED passkeys.js (Enhanced with better debugging) =====

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

const expectedOrigin = [process.env.PASSKEY_ORIGIN];
const expectedRPID = process.env.PASSKEY_RPID;

// In-memory challenge store for demo (use DB/session in production)
import challengeStore from "../utils/challengeStore.js";

// Utility function to generate consistent tempUserId
const generateTempUserId = (email) => {
    return btoa(email).replace(/[^a-zA-Z0-9]/g, '');
};

// Utility function to clean up expired challenges
const cleanupExpiredChallenges = () => {
    const now = Date.now();
    const maxAge = 5 * 60 * 1000; // 5 minutes

    for (const [key, value] of challengeStore.entries()) {
        if (value.timestamp && now - value.timestamp > maxAge) {
            console.log("🧹 Cleaning up expired challenge:", key);
            challengeStore.delete(key);
        }
    }
};

// Clean up expired challenges every minute
setInterval(cleanupExpiredChallenges, 60000);

// -----------------------------
// 🔧 ENHANCED: Temporary Passkey Registration Challenge (for signup flow)
// -----------------------------
router.post("/passkey-challenge-temp", async (req, res) => {
    try {
        const { tempUserId, email, firstName, lastName, userName } = req.body;

        if (!tempUserId || !email || !firstName || !lastName) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        console.log("🔍 Creating temporary passkey challenge for:", email);
        console.log("🔍 Using tempUserId:", tempUserId);

        // Clean up expired challenges first
        cleanupExpiredChallenges();

        // Use tempUserId as Buffer for v13
        const userIdBuffer = Buffer.from(tempUserId, 'utf8');

        const options = await generateRegistrationOptions({
            rpName: "Riffn",
            rpID: "localhost", // replace with your domain in production
            userID: userIdBuffer,
            userName: userName || email,
            userDisplayName: `${firstName} ${lastName}`,
            attestationType: "none",
            authenticatorSelection: {
                userVerification: "preferred",
                residentKey: "preferred"
            },
            supportedAlgorithmIDs: [-7, -257], // ES256 and RS256
            timeout: 60000,
        });

        // Store challenge with temporary ID for later use
        challengeStore.set(tempUserId, {
            challenge: options.challenge,
            email,
            firstName,
            lastName,
            userName,
            timestamp: Date.now()
        });

        console.log("✅ Challenge stored with key:", tempUserId);
        console.log("📊 Current challenge store keys:", Array.from(challengeStore.keys()));

        res.json(options);
    } catch (err) {
        console.error("❌ Temporary passkey challenge error:", err);
        res.status(500).json({
            error: "Failed to generate temporary passkey challenge",
            details: err.message
        });
    }
});

// -----------------------------
// 🔧 ENHANCED: Verify Passkey Registration (with fallback lookup)
// -----------------------------
router.post("/users/:userId/passkeys", async (req, res) => {
    const { userId } = req.params;
    const { attestationResponse, tempUserId } = req.body;

    try {
        console.log("🔍 Passkey verification for userId:", userId);
        console.log("🔍 Looking for challenge with tempUserId:", tempUserId);

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        // Clean up expired challenges first
        cleanupExpiredChallenges();

        // 🔧 FIX: Try to find challenge with multiple strategies
        let expectedChallenge;
        let challengeKey;

        // Strategy 1: Use provided tempUserId
        if (tempUserId) {
            expectedChallenge = challengeStore.get(tempUserId);
            challengeKey = tempUserId;
            console.log("🔍 Strategy 1 (tempUserId):", tempUserId, "found:", !!expectedChallenge);
        }

        // Strategy 2: Use real userId as fallback
        if (!expectedChallenge) {
            expectedChallenge = challengeStore.get(userId);
            challengeKey = userId;
            console.log("🔍 Strategy 2 (userId):", userId, "found:", !!expectedChallenge);
        }

        // Strategy 3: Try generating tempUserId from user email
        if (!expectedChallenge && user.email) {
            const generatedTempUserId = generateTempUserId(user.email);
            expectedChallenge = challengeStore.get(generatedTempUserId);
            challengeKey = generatedTempUserId;
            console.log("🔍 Strategy 3 (generated tempUserId):", generatedTempUserId, "found:", !!expectedChallenge);
        }

        if (!expectedChallenge) {
            console.log("❌ No challenge found with any strategy");
            console.log("📊 Available challenge keys:", Array.from(challengeStore.keys()));
            return res.status(400).json({ error: "No challenge found for this user" });
        }

        console.log("✅ Found challenge with key:", challengeKey);

        const verification = await verifyRegistrationResponse({
            response: attestationResponse,
            expectedChallenge: expectedChallenge.challenge || expectedChallenge,
            expectedOrigin,
            expectedRPID,
        });

        if (!verification.verified) {
            console.log("❌ Passkey verification failed");
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

        // Clean up the challenge with correct key
        challengeStore.delete(challengeKey);
        console.log("✅ Passkey registered and challenge cleaned up");

        res.json({ success: true });
    } catch (err) {
        console.error("❌ Passkey registration verification error:", err);
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
        console.log("🔍 Login challenge for email:", email);

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

        challengeStore.set(user._id.toString(), {
            challenge: options.challenge,
            timestamp: Date.now()
        });

        console.log("✅ Generated login challenge for user:", user._id);

        res.json({ options, userId: user._id });
    } catch (err) {
        console.error("❌ Login challenge error:", err);
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
        console.log("🔍 Login verification for userId:", userId);

        const user = await User.findById(userId);
        if (!user || !user.passkeyId) {
            return res.status(404).json({ error: "User or passkey not found" });
        }

        const challengeData = challengeStore.get(userId);
        if (!challengeData) {
            return res.status(400).json({ error: "No challenge found for login" });
        }

        const verification = await verifyAuthenticationResponse({
            response: assertionResponse,
            expectedChallenge: challengeData.challenge,
            expectedOrigin,
            expectedRPID,
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

        console.log("✅ Passkey login successful");

        res.json({ user });
    } catch (err) {
        console.error("❌ Login verification error:", err);
        res.status(500).json({
            error: "Passkey login verification failed",
            details: err.message
        });
    }
});

// Debug endpoint to check challenge store status
router.get("/debug/challenges", (req, res) => {
    const challenges = Array.from(challengeStore.entries()).map(([key, value]) => ({
        key,
        hasChallenge: !!value.challenge,
        timestamp: value.timestamp,
        email: value.email || 'N/A'
    }));

    res.json({
        totalChallenges: challengeStore.size,
        challenges
    });
});

export default router;