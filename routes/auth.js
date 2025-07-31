import express from 'express';
import User from '../models/User.js';
import bcrypt from 'bcrypt';
import { generateRegOptions, verifyReg } from '../controllers/webauthnController.js';
import {
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import base64url from 'base64url';


const router = express.Router();

router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user)
            return res.status(401).json({ message: 'Invalid email or password' });

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid)
            return res.status(401).json({ message: 'Invalid email or password' });

        const { password: _, ...safeUser } = user.toObject();
        res.json({ user: safeUser });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Server error" });
    }
});

router.post('/webauthn/register/options', generateRegOptions);
router.post('/webauthn/register/verify', verifyReg);

router.post('/webauthn/login/options', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || user.credentials.length === 0) {
            return res.status(404).json({ message: 'No passkey registered' });
        }

        const options = generateAuthenticationOptions({
            allowCredentials: user.credentials.map((cred) => ({
                id: base64url.encode(cred.credentialID),
                type: 'public-key',
                transports: ['internal'],
            })),
            userVerification: 'preferred',
            rpID: 'localhost', // or your domain in prod
        });

        req.session.challenge = options.challenge;
        req.session.email = email;

        res.json(options);
    } catch (err) {
        console.error('Error generating auth options:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

router.post('/webauthn/login/verify', async (req, res) => {
    const { authResponse } = req.body;
    const { challenge, email } = req.session;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: 'User not found' });

        const cred = user.credentials.find((c) =>
            base64url.encode(c.credentialID) === authResponse.id
        );

        if (!cred) return res.status(400).json({ message: 'Credential not recognized' });

        const verification = await verifyAuthenticationResponse({
            response: authResponse,
            expectedChallenge: challenge,
            expectedOrigin: process.env.NODE_ENV === 'production' ? 'https://riffn.vercel.app' : 'http://localhost:5173',
            expectedRPID: 'localhost',
            authenticator: {
                credentialID: cred.credentialID,
                credentialPublicKey: cred.publicKey,
                counter: cred.counter,
            },
        });

        if (!verification.verified) {
            return res.status(401).json({ message: 'Authentication failed' });
        }

        // Update counter to prevent replay attacks
        cred.counter = verification.authenticationInfo.newCounter;
        await user.save();

        const { password, ...safeUser } = user.toObject();
        res.json({ user: safeUser });

    } catch (err) {
        console.error('Login verify error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});



export default router;
