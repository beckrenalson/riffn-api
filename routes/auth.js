import express from 'express';
import bcrypt from 'bcrypt';
import User from '../models/User.js';
import dotenv from 'dotenv';
import base64url from "base64url";
import { Buffer } from "buffer";
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { randomBytes } from 'crypto';

dotenv.config();

const router = express.Router();

// Passkey configuration
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

// Utility function to convert base64url to base64
const base64urlToBase64 = (base64url) => {
    return base64url.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - base64url.length % 4) % 4);
};

// -----------------------------
// PASSWORD LOGIN
// -----------------------------
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    console.log('=== PASSWORD LOGIN REQUEST ===');
    console.log('Email:', email);
    console.log('Has password:', !!password);

    try {
        const user = await User.findOne({ email });
        if (!user) {
            console.log('User not found for email:', email);
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        console.log('User found:', user.email);

        if (!password) {
            console.log('No password provided');
            return res.status(400).json({ message: 'Password is required for this route' });
        }

        // Validate password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            console.log('Invalid password for:', email);
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Strip sensitive fields
        const { password: _, ...safeUser } = user.toObject();

        console.log('Password login successful for:', email);
        return res.json({ user: safeUser, message: 'Password login successful' });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// -----------------------------
// PASSKEY REGISTRATION CHALLENGE (for signup flow)
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
            rpID: expectedRPID,
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
// VERIFY PASSKEY REGISTRATION
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

        // Try to find challenge with multiple strategies
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
// UNIFIED LOGIN ENDPOINT (Password + Passkey)
// -----------------------------
router.post('/users/passkey-login-challenge', async (req, res) => {
    const { email, password, requestPasskey, passkeyCredential, tempUserId } = req.body;

    // Add initial debugging
    console.log('=== LOGIN REQUEST ===');
    console.log('Request body keys:', Object.keys(req.body));
    console.log('Email:', email);
    console.log('Has password:', !!password);
    console.log('Request passkey:', !!requestPasskey);
    console.log('Has passkey credential:', !!passkeyCredential);
    console.log('Temp user ID:', tempUserId);

    try {
        const user = await User.findOne({ email });
        if (!user) {
            console.log('User not found for email:', email);
            return res.status(401).json({ message: 'Invalid email or password/passkey' });
        }
        console.log('User found:', user.email);

        // -----------------
        // PASSWORD LOGIN
        // -----------------
        if (password) {
            console.log('Processing password login');
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) return res.status(401).json({ message: 'Invalid email or password' });

            const { password: _, ...safeUser } = user.toObject();
            return res.json({ user: safeUser, message: 'Password login successful' });
        }

        // -----------------
        // PASSKEY LOGIN - Step A: initiate challenge
        // -----------------
        if (requestPasskey && !passkeyCredential) {
            console.log('Processing passkey challenge request');
            if (!user.passkeyId) {
                console.log('User has no passkey ID stored');
                return res.status(404).json({ message: 'User has no passkey' });
            }

            const challenge = randomBytes(32).toString('base64url');
            const tempUserId = Buffer.from(email).toString('base64url');

            challengeStore.set(tempUserId, { challenge, userId: user._id, timestamp: Date.now() });

            const { password: _, ...safeUser } = user.toObject();
            console.log('Sending challenge response, tempUserId:', tempUserId);
            return res.json({ tempUserId, challenge, userName: user.userName, user: safeUser });
        }

        // -----------------
        // PASSKEY LOGIN - Step B: verify passkey response
        // -----------------
        if (passkeyCredential) {
            console.log('Processing passkey credential verification');
            if (!tempUserId) return res.status(400).json({ message: 'Missing tempUserId for passkey verification' });

            const challengeData = challengeStore.get(tempUserId);
            if (!challengeData) return res.status(400).json({ message: 'Challenge missing or expired' });

            // Add debugging logs
            console.log('=== PASSKEY VERIFICATION DEBUG ===');
            console.log('- User has passkeyId:', !!user.passkeyId);
            console.log('- User has publicKey:', !!user.publicKey);
            console.log('- User passkeyCounter:', user.passkeyCounter);
            console.log('- Expected Origin:', expectedOrigin);
            console.log('- Expected RPID:', expectedRPID);
            console.log('- Received credential structure:', Object.keys(passkeyCredential));

            // Handle different possible formats of stored credentials
            let credentialID, publicKey;

            // Check if passkeyId is stored as base64url or base64
            try {
                if (user.passkeyId.includes('-') || user.passkeyId.includes('_')) {
                    // It's base64url, convert to base64 first
                    credentialID = Buffer.from(base64urlToBase64(user.passkeyId), 'base64');
                } else {
                    // It's regular base64
                    credentialID = Buffer.from(user.passkeyId, 'base64');
                }
            } catch (err) {
                console.error('Error parsing credentialID:', err);
                return res.status(400).json({ message: 'Invalid stored credential ID' });
            }

            // Handle publicKey similarly
            try {
                if (user.publicKey.includes('-') || user.publicKey.includes('_')) {
                    // It's base64url
                    publicKey = Buffer.from(base64urlToBase64(user.publicKey), 'base64');
                } else {
                    // It's regular base64
                    publicKey = Buffer.from(user.publicKey, 'base64');
                }
            } catch (err) {
                console.error('Error parsing publicKey:', err);
                return res.status(400).json({ message: 'Invalid stored public key' });
            }

            // Ensure counter is a number
            const currentCounter = typeof user.passkeyCounter === 'number' ? user.passkeyCounter : 0;
            console.log('Using counter:', currentCounter);

            let verification;
            try {
                verification = await verifyAuthenticationResponse({
                    response: passkeyCredential,
                    expectedChallenge: challengeData.challenge,
                    expectedOrigin,
                    expectedRPID,
                    authenticator: {
                        credentialID,
                        counter: currentCounter,
                        credentialPublicKey: publicKey,
                    },
                });
                console.log('Verification succeeded with credentialPublicKey!');
            } catch (verificationError) {
                console.log('credentialPublicKey failed:', verificationError.message);
                console.log('Trying with publicKey field name...');

                try {
                    verification = await verifyAuthenticationResponse({
                        response: passkeyCredential,
                        expectedChallenge: challengeData.challenge,
                        expectedOrigin,
                        expectedRPID,
                        authenticator: {
                            credentialID,
                            counter: currentCounter,
                            publicKey,
                        },
                    });
                    console.log('Verification succeeded with publicKey!');
                } catch (secondError) {
                    console.error('Both verification attempts failed');
                    console.error('credentialPublicKey error:', verificationError.message);
                    console.error('publicKey error:', secondError.message);
                    console.error('Full error stack:', secondError.stack);
                    return res.status(400).json({ message: 'Passkey verification failed', error: secondError.message });
                }
            }

            console.log('Verification result:', verification);
            console.log('Verification verified:', verification.verified);
            console.log('Verification authenticationInfo:', verification.authenticationInfo);

            if (!verification.verified) {
                console.error('Passkey verification failed');
                return res.status(401).json({ message: 'Passkey authentication failed' });
            }

            // Update counter - handle different possible structures
            if (verification.authenticationInfo && typeof verification.authenticationInfo.newCounter !== 'undefined') {
                user.passkeyCounter = verification.authenticationInfo.newCounter;
                console.log('Updated counter to:', verification.authenticationInfo.newCounter);
            } else if (verification.authenticationInfo && typeof verification.authenticationInfo.counter !== 'undefined') {
                user.passkeyCounter = verification.authenticationInfo.counter;
                console.log('Updated counter to (alt structure):', verification.authenticationInfo.counter);
            } else {
                console.log('No counter found in verification result, keeping existing counter:', user.passkeyCounter);
            }
            await user.save();

            // Clean up challenge
            challengeStore.delete(tempUserId);

            const { password: _, ...safeUser } = user.toObject();
            return res.json({ user: safeUser, message: 'Passkey login successful' });
        }

        // -----------------
        // If none of the above matched
        // -----------------
        return res.status(400).json({ message: 'No login method provided' });

    } catch (err) {
        console.error('Login error:', err);
        console.error('Error stack:', err.stack);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// -----------------------------
// LEGACY PASSKEY LOGIN (kept for backward compatibility)
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

// -----------------------------
// DEBUG ENDPOINT
// -----------------------------
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