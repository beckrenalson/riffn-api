import express from 'express';
import bcrypt from 'bcrypt';
import User from '../models/User.js';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import base64url from "base64url";
import { Buffer } from "buffer";
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from "@simplewebauthn/server";

dotenv.config();

const router = express.Router();

// Helper function to generate a JWT token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '1h', // Token expires in 1 hour
    });
};

// Helper function to generate a Refresh Token
const generateRefreshToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, {
        expiresIn: '7d', // Refresh token expires in 7 days
    });
};

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

        const token = generateToken(user._id);
        const refreshToken = generateRefreshToken(user._id);

        res.cookie('jwt', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'strict', // Changed to 'None' for cross-site in production
            maxAge: 3600000 // 1 hour
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'strict', // Changed to 'None' for cross-site in production
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

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

        // Add this before the passkey verification section
        if (typeof user.passkeyCounter !== 'number') {
            console.log('Fixing undefined passkeyCounter for user:', user.email);
            user.passkeyCounter = 0;
            await user.save();
        }

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

        // Replace the PASSKEY LOGIN - Step A section with this fixed version:

        // -----------------
        // PASSKEY LOGIN - Step A: initiate challenge
        // -----------------
        if (requestPasskey && !passkeyCredential) {
            console.log('Processing passkey challenge request');

            if (!user.passkeyId || !user.publicKey) {
                console.log('User has no passkey credentials stored. Cannot initiate passkey login.');
                return res.status(404).json({ message: 'User has not registered a passkey' });
            }

            // Create Buffers from the stored strings.
            let credentialIDBuffer;
            let credentialPublicKeyBuffer;

            try {
                credentialIDBuffer = base64url.toBuffer(user.passkeyId);
                credentialPublicKeyBuffer = base64url.toBuffer(user.publicKey);
            } catch (bufferError) {
                console.error('Buffer conversion error:', bufferError);
                return res.status(500).json({ message: 'Passkey data is malformed' });
            }

            // Check if the conversion resulted in an undefined or empty Buffer.
            if (!credentialIDBuffer || credentialIDBuffer.length === 0 || !credentialPublicKeyBuffer || credentialPublicKeyBuffer.length === 0) {
                console.error('Buffer conversion resulted in empty or invalid data.');
                return res.status(500).json({ message: 'Passkey data is malformed after conversion.' });
            }

            // FIX: Create proper credential descriptor for allowCredentials
            // Use the original base64url string, not the Buffer
            const allowCredentials = [{
                id: user.passkeyId, // Use the stored base64url string directly
                type: 'public-key',
                transports: ['internal', 'hybrid'] // Add common transports
            }];

            const options = await generateAuthenticationOptions({
                rpID: expectedRPID,
                allowCredentials: allowCredentials, // Use proper credential descriptors
                userVerification: "preferred",
            });

            const tempUserId = generateTempUserId(email);

            // Store both challenge and authenticator data for verification step
            challengeStore.set(tempUserId, {
                challenge: options.challenge,
                userId: user._id,
                timestamp: Date.now(),
                authenticator: {
                    credentialID: credentialIDBuffer,
                    credentialPublicKey: credentialPublicKeyBuffer,
                    counter: user.passkeyCounter || 0, // Ensure counter is always a number
                }
            });

            const { password: _, ...safeUser } = user.toObject();
            console.log('Sending challenge response, tempUserId:', tempUserId);
            return res.json({ tempUserId, challenge: options.challenge, userName: user.userName, user: safeUser });
        }

        // -----------------
        // PASSKEY LOGIN - Step B: verify passkey response
        // -----------------
        if (passkeyCredential) {
            console.log('Processing passkey credential verification');
            if (!tempUserId) return res.status(400).json({ message: 'Missing tempUserId for passkey verification' });

            const challengeData = challengeStore.get(tempUserId);
            if (!challengeData) return res.status(400).json({ message: 'Challenge missing or expired' });

            // Ensure passkeyCounter is a number (safety check for existing users)
            if (typeof user.passkeyCounter !== 'number') {
                console.log('⚠️  Fixing undefined passkeyCounter for user:', user.email);
                user.passkeyCounter = 0;
                await user.save();
            }

            // Add debugging logs
            console.log('=== PASSKEY VERIFICATION DEBUG ===');
            console.log('- User has passkeyId:', !!user.passkeyId);
            console.log('- User has publicKey:', !!user.publicKey);
            console.log('- User passkeyCounter:', user.passkeyCounter);
            console.log('- Expected Origin:', expectedOrigin);
            console.log('- Expected RPID:', expectedRPID);
            console.log('- Received credential structure:', Object.keys(passkeyCredential));

            // Debug challenge data
            console.log('=== CHALLENGE DATA DEBUG ===');
            console.log('- challengeData keys:', Object.keys(challengeData));
            console.log('- challengeData.credential exists:', !!challengeData.credential);
            console.log('- challengeData.authenticator exists (legacy):', !!challengeData.authenticator);

            // Create credential object for v13 API
            let credential;

            if (challengeData.credential) {
                console.log('Using stored credential from challenge (v13 format)');
                credential = challengeData.credential;
            } else if (challengeData.authenticator) {
                console.log('Converting legacy authenticator to v13 credential format');
                // Convert legacy format to v13 format
                credential = {
                    id: user.passkeyId,
                    publicKey: challengeData.authenticator.credentialPublicKey,
                    counter: challengeData.authenticator.counter,
                    transports: ['internal', 'hybrid']
                };
            } else {
                console.log('Creating fallback credential from user data');
                try {
                    credential = {
                        id: user.passkeyId,
                        publicKey: base64url.toBuffer(user.publicKey),
                        counter: user.passkeyCounter || 0,
                        transports: ['internal', 'hybrid']
                    };
                } catch (bufferError) {
                    console.error('Buffer conversion error:', bufferError);
                    return res.status(500).json({ message: 'Failed to process passkey data' });
                }
            }

            // Debug the credential object
            console.log('=== CREDENTIAL DEBUG ===');
            console.log('- Credential id:', credential.id);
            console.log('- Credential counter:', credential.counter);
            console.log('- Counter type:', typeof credential.counter);
            console.log('- User passkeyCounter:', user.passkeyCounter);
            console.log('- PublicKey buffer length:', credential.publicKey ? credential.publicKey.length : 'undefined');
            console.log('- Transports:', credential.transports);

            let verification;
            try {
                console.log('=== CALLING VERIFICATION ===');
                console.log('- About to call verifyAuthenticationResponse with v13 API');

                // v13 API: use 'credential' parameter
                verification = await verifyAuthenticationResponse({
                    response: passkeyCredential,
                    expectedChallenge: challengeData.challenge,
                    expectedOrigin,
                    expectedRPID,
                    credential: credential, // v13 API uses 'credential' instead of 'authenticator'
                });

                console.log('✅ Verification succeeded!');
            } catch (verificationError) {
                console.error('❌ Passkey verification failed:', verificationError.message);
                console.error('❌ Full error:', verificationError);

                // Debug the inputs to verification
                console.error('=== VERIFICATION INPUT DEBUG ===');
                console.error('- passkeyCredential structure:', {
                    id: !!passkeyCredential.id,
                    rawId: !!passkeyCredential.rawId,
                    response: !!passkeyCredential.response,
                    type: passkeyCredential.type
                });
                console.error('- Challenge exists:', !!challengeData.challenge);
                console.error('- Credential structure:', {
                    id: !!credential.id,
                    publicKey: !!credential.publicKey,
                    counter: credential.counter,
                    counterType: typeof credential.counter,
                    transports: credential.transports
                });

                return res.status(400).json({ message: 'Passkey verification failed', error: verificationError.message });
            }

            // Update counter - handle different possible structures
            const { newCounter } = verification.authenticationInfo;
            if (typeof newCounter !== 'undefined') {
                user.passkeyCounter = newCounter;
                console.log('Updated counter to:', newCounter);
            } else {
                console.log('No new counter found in verification result, keeping existing counter:', user.passkeyCounter);
            }
            await user.save();

            // Clean up challenge
            challengeStore.delete(tempUserId);

            const { password: _, ...safeUser } = user.toObject();
            const token = generateToken(user._id);
            const refreshToken = generateRefreshToken(user._id);

            res.cookie('jwt', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'strict',
                maxAge: 3600000
            });

            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
            });

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
// LOGOUT
// -----------------------------
router.post('/logout', (req, res) => {
    res.cookie('jwt', '', {
        httpOnly: true,
        expires: new Date(0),
        maxAge: 0 // Explicitly set maxAge to 0
    });
    res.cookie('refreshToken', '', {
        httpOnly: true,
        expires: new Date(0),
        maxAge: 0 // Explicitly set maxAge to 0
    });
    res.status(200).json({ message: 'Logged out successfully' });
});

// -----------------------------
// REFRESH TOKEN ENDPOINT
// -----------------------------
router.post('/refresh-token', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ message: 'No refresh token provided' });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        const user = await User.findById(decoded.id).select('-password');
        if (!user) {
            return res.status(401).json({ message: 'Invalid refresh token - user not found' });
        }

        const newToken = generateToken(user._id);
        const newRefreshToken = generateRefreshToken(user._id);

        res.cookie('jwt', newToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'strict',
            maxAge: 3600000 // 1 hour
        });

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        console.log('Cookies set on refresh token:', req.cookies); // Debugging: log cookies
        return res.json({ message: 'Token refreshed successfully' });

    } catch (error) {
        console.error('Refresh token error:', error);
        return res.status(401).json({ message: 'Not authorized, refresh token failed' });
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