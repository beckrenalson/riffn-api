import express from 'express';
import bcrypt from 'bcrypt';
import User from '../models/User.js';
import { randomBytes } from 'crypto';
import challengeStore from '../utils/challengeStore.js';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';

const router = express.Router();

const expectedOrigin = [process.env.PASSKEY_ORIGIN];
const expectedRPID = process.env.PASSKEY_RPID;

router.post('/login', async (req, res) => {
    const { email, password, requestPasskey, passkeyCredential, tempUserId } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ message: 'Invalid email or password/passkey' });

        // -----------------
        // 1️⃣ Password login
        // -----------------
        if (password) {
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) return res.status(401).json({ message: 'Invalid email or password' });

            const { password: _, ...safeUser } = user.toObject();
            return res.json({ user: safeUser, message: 'Password login successful' });
        }

        // -----------------
        // 2️⃣ Passkey login Step A: initiate challenge
        // -----------------
        if (requestPasskey && !passkeyCredential) {
            if (!user.passkeyId) return res.status(404).json({ message: 'User has no passkey' });

            const challenge = randomBytes(32).toString('base64url');
            const tempUserId = Buffer.from(email).toString('base64url');

            challengeStore.set(tempUserId, { challenge, userId: user._id, timestamp: Date.now() });

            const { password: _, ...safeUser } = user.toObject();
            return res.json({ tempUserId, challenge, userName: user.userName, user: safeUser });
        }

        // -----------------
        // Step B: verify passkey response
        // -----------------
        if (passkeyCredential) {
            if (!tempUserId) return res.status(400).json({ message: 'Missing tempUserId for passkey verification' });

            const challengeData = challengeStore.get(tempUserId);
            if (!challengeData) return res.status(400).json({ message: 'Challenge missing or expired' });

            const verification = await verifyAuthenticationResponse({
                response: passkeyCredential,
                expectedChallenge: challengeData.challenge,
                expectedOrigin,
                expectedRPID,
                authenticator: {
                    credentialID: Buffer.from(user.passkeyId, 'base64'),
                    counter: user.passkeyCounter,
                    publicKey: Buffer.from(user.publicKey, 'base64'),
                },
            });

            if (!verification.verified) return res.status(401).json({ message: 'Passkey authentication failed' });

            // Update counter
            user.passkeyCounter = verification.authenticationInfo.newCounter;
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
        res.status(500).json({ message: 'Server error' });
    }
});

export default router;
