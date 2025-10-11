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

const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '1h',
    });
};

const generateRefreshToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, {
        expiresIn: '7d',
    });
};

const expectedOrigin = [process.env.PASSKEY_ORIGIN];
const expectedRPID = process.env.PASSKEY_RPID;

import challengeStore from "../utils/challengeStore.js";

const generateTempUserId = (email) => {
    return btoa(email).replace(/[^a-zA-Z0-9]/g, '');
};


const base64urlToBase64 = (base64url) => {
    return base64url.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - base64url.length % 4) % 4);
};

router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        if (!password) {
            return res.status(400).json({ message: 'Password is required for this route' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const { password: _, ...safeUser } = user.toObject();

        const token = generateToken(user._id);
        const refreshToken = generateRefreshToken(user._id);

        res.cookie('jwt', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            maxAge: 3600000
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ user: safeUser, message: 'Password login successful' });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

router.post("/passkey-challenge-temp", async (req, res) => {
    try {
        const { tempUserId, email, firstName, lastName, userName } = req.body;

        if (!tempUserId || !email || !firstName || !lastName) {
            return res.status(400).json({ error: "Missing required fields" });
        }


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
            supportedAlgorithmIDs: [-7, -257],
            timeout: 60000,
        });

        challengeStore.set(tempUserId, {
            challenge: options.challenge,
            email,
            firstName,
            lastName,
            userName,
            timestamp: Date.now()
        });

        res.json(options);
    } catch (err) {
        console.error("Temporary passkey challenge error:", err);
        res.status(500).json({
            error: "Failed to generate temporary passkey challenge",
            details: err.message
        });
    }
});

router.post("/users/:userId/passkeys", async (req, res) => {
    const { userId } = req.params;
    const { attestationResponse, tempUserId } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: "User not found" });


        let expectedChallenge;
        let challengeKey;

        if (tempUserId) {
            expectedChallenge = challengeStore.get(tempUserId);
            challengeKey = tempUserId;
        }

        if (!expectedChallenge) {
            expectedChallenge = challengeStore.get(userId);
            challengeKey = userId;
        }

        if (!expectedChallenge && user.email) {
            const generatedTempUserId = generateTempUserId(user.email);
            expectedChallenge = challengeStore.get(generatedTempUserId);
            challengeKey = generatedTempUserId;
        }

        if (!expectedChallenge) {
            return res.status(400).json({ error: "No challenge found for this user" });
        }

        if (typeof user.passkeyCounter !== 'number') {
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
            return res.status(400).json({ error: "Passkey registration failed" });
        }

        const credential = verification.registrationInfo?.credential;
        if (!credential) {
            throw new Error("No credential found in verification result");
        }

        const { id: credentialID, publicKey: credentialPublicKey, counter } = credential;

        user.passkeyId = base64url.encode(credentialID);
        user.publicKey = base64url.encode(credentialPublicKey);
        user.passkeyCounter = counter || 0;
        await user.save();

        challengeStore.delete(challengeKey);

        res.json({ success: true });
    } catch (err) {
        console.error("Passkey registration verification error:", err);
        res.status(500).json({
            error: "Passkey registration verification failed",
            details: err.message
        });
    }
});

router.post('/users/passkey-login-challenge', async (req, res) => {
    const { email, password, requestPasskey, passkeyCredential, tempUserId } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password/passkey' });
        }

        if (password) {
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) return res.status(401).json({ message: 'Invalid email or password' });

            const { password: _, ...safeUser } = user.toObject();
            return res.json({ user: safeUser, message: 'Password login successful' });
        }

        if (requestPasskey && !passkeyCredential) {
            if (!user.passkeyId || !user.publicKey) {
                return res.status(404).json({ message: 'User has not registered a passkey' });
            }

            let credentialIDBuffer;
            let credentialPublicKeyBuffer;

            try {
                credentialIDBuffer = base64url.toBuffer(user.passkeyId);
                credentialPublicKeyBuffer = base64url.toBuffer(user.publicKey);
            } catch (bufferError) {
                console.error('Buffer conversion error:', bufferError);
                return res.status(500).json({ message: 'Passkey data is malformed' });
            }

            if (!credentialIDBuffer || credentialIDBuffer.length === 0 || !credentialPublicKeyBuffer || credentialPublicKeyBuffer.length === 0) {
                console.error('Buffer conversion resulted in empty or invalid data.');
                return res.status(500).json({ message: 'Passkey data is malformed after conversion.' });
            }

            const allowCredentials = [{
                id: user.passkeyId,
                type: 'public-key',
                transports: ['internal', 'hybrid']
            }];

            const options = await generateAuthenticationOptions({
                rpID: expectedRPID,
                allowCredentials: allowCredentials,
                userVerification: "preferred",
            });

            const tempUserId = generateTempUserId(email);

            challengeStore.set(tempUserId, {
                challenge: options.challenge,
                userId: user._id,
                timestamp: Date.now(),
                authenticator: {
                    credentialID: credentialIDBuffer,
                    credentialPublicKey: credentialPublicKeyBuffer,
                    counter: user.passkeyCounter || 0,
                }
            });

            const { password: _, ...safeUser } = user.toObject();
            return res.json({ tempUserId, challenge: options.challenge, userName: user.userName, user: safeUser });
        }

        if (passkeyCredential) {
            if (!tempUserId) return res.status(400).json({ message: 'Missing tempUserId for passkey verification' });

            const challengeData = challengeStore.get(tempUserId);
            if (!challengeData) return res.status(400).json({ message: 'Challenge missing or expired' });

            if (typeof user.passkeyCounter !== 'number') {
                user.passkeyCounter = 0;
                await user.save();
            }

            let credential;

            if (challengeData.credential) {
                credential = challengeData.credential;
            } else if (challengeData.authenticator) {
                credential = {
                    id: user.passkeyId,
                    publicKey: challengeData.authenticator.credentialPublicKey,
                    counter: challengeData.authenticator.counter,
                    transports: ['internal', 'hybrid']
                };
            } else {
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

            let verification;
            try {
                verification = await verifyAuthenticationResponse({
                    response: passkeyCredential,
                    expectedChallenge: challengeData.challenge,
                    expectedOrigin,
                    expectedRPID,
                    credential: credential,
                });
            } catch (verificationError) {
                console.error('Passkey verification failed:', verificationError);
                return res.status(400).json({ message: 'Passkey verification failed', error: verificationError.message });
            }

            const { newCounter } = verification.authenticationInfo;
            if (typeof newCounter !== 'undefined') {
                user.passkeyCounter = newCounter;
            }
            await user.save();

            challengeStore.delete(tempUserId);

            const { password: _, ...safeUser } = user.toObject();
            const token = generateToken(user._id);
            const refreshToken = generateRefreshToken(user._id);

            res.cookie('jwt', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
                maxAge: 3600000
            });

            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
                maxAge: 7 * 24 * 60 * 60 * 1000
            });

            return res.json({ user: safeUser, message: 'Passkey login successful' });
        }

        return res.status(400).json({ message: 'No login method provided' });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

router.post('/logout', (req, res) => {
    res.cookie('jwt', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
        expires: new Date(0),
        maxAge: 0
    });
    res.cookie('refreshToken', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
        expires: new Date(0),
        maxAge: 0
    });
    res.status(200).json({ message: 'Logged out successfully' });
});

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
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            maxAge: 3600000
        });

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ message: 'Token refreshed successfully' });

    } catch (error) {
        console.error('Refresh token error:', error);
        return res.status(401).json({ message: 'Not authorized, refresh token failed' });
    }
});

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