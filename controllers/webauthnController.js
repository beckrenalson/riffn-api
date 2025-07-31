import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
} from '@simplewebauthn/server';
import User from '../models/User.js';
import base64url from 'base64url';

// Double-check this constant!
const rpID = 'localhost';
const origin = 'http://localhost:5173'; // your frontend origin

export const generateRegOptions = async (req, res) => {
    // Wrap the *entire* function's core logic in a more encompassing try-catch
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email is required' });

        let user = await User.findOne({ email });
        if (!user) {
            console.log(`User with email ${email} not found, creating new user.`);
            user = await User.create({
                userName: email.split('@')[0],
                email,
                password: 'dummy-password',
                credentials: [],
            });
            console.log('New user created:', user);
        } else {
            console.log('Existing user found:', user);
        }

        console.log('User ID:', user._id);
        console.log('User Name:', user.userName);
        console.log('Type of User ID:', typeof user._id);
        console.log('Type of User Name:', typeof user.userName);

        // Ensure rpID is consistent with frontend
        console.log('rpID used:', rpID);

        const userID = Buffer.from(user._id.toString(), 'utf8');
        console.log('Converted UserID (Buffer):', userID);
        console.log('Length of Converted UserID:', userID.length);


        let options;
        try {
            // Try to catch errors specifically from this call
            options = generateRegistrationOptions({
                rpName: 'Riffn',
                rpID, // Using the constant
                userID,
                userName: user.userName,
                timeout: 60000,
                attestationType: 'indirect',
                authenticatorSelection: {
                    userVerification: 'preferred',
                },
            });
        } catch (innerError) {
            console.error('ERROR during generateRegistrationOptions call:', innerError);
            // Re-throw to ensure it's caught by the outer catch, or handle specifically
            throw innerError;
        }


        console.log('Backend Generated Options:', JSON.stringify(options, null, 2));
        console.log('Backend Options Challenge:', options.challenge);

        req.session.challenge = options.challenge;
        req.session.email = email;

        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ error: 'Session save error' });
            }
            res.json(options);
        });
    } catch (outerError) { // This catch will now get errors from anywhere above, including the inner try/catch
        console.error('!!!! FATAL generateRegOptions error:', outerError);
        // Log full stack trace and error object
        if (outerError instanceof Error) {
            console.error('Error message:', outerError.message);
            console.error('Error stack:', outerError.stack);
        } else {
            console.error('Non-Error object caught:', outerError);
        }

        res.status(500).json({ error: 'Internal server error during passkey generation', details: outerError.message || 'unknown error' });
    }
};

export const verifyReg = async (req, res) => {
    try {
        const { attestationResponse } = req.body;
        const { challenge, email } = req.session;

        if (!challenge || !email) {
            return res.status(400).json({ error: 'Missing challenge or email in session' });
        }

        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const verification = await verifyRegistrationResponse({
            response: attestationResponse,
            expectedChallenge: challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });

        if (verification.verified) {
            user.credentials.push({
                credentialID: Buffer.from(verification.registrationInfo.credentialID),
                publicKey: Buffer.from(verification.registrationInfo.credentialPublicKey),
                counter: verification.registrationInfo.counter,
            });
            await user.save();

            // Clear challenge from session after successful verification
            delete req.session.challenge;
            req.session.save((err) => {
                if (err) console.error('Error saving session after clearing challenge:', err);
            });

        }

        res.json({ verified: verification.verified });
    } catch (error) {
        console.error('verifyReg error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};
