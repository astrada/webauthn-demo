import express from 'express';
import session from 'express-session';
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
} from '@simplewebauthn/server';
import {
    RegistrationResponseJSON,
} from '@simplewebauthn/typescript-types';

const app = express();
const rpName = 'WebAuthn Demo';
const rpID = 'localhost';
const origin = `https://${rpID}`;

// In-memory user store (replace with database in production)
const users = new Map<string, {
    id: string;
    username: string;
    password: string;
    devices: Array<{
        credentialID: Buffer;
        credentialPublicKey: Buffer;
        counter: number;
    }>;
}>();

users.set('test', {
    id: '1',
    username: 'test',
    password: 'password',
    devices: [],
});

app.use(express.json());
app.use(session({
    secret: 'webauthn-demo-secret-key',
    resave: false,
    saveUninitialized: true,
}));

interface RegistrationOptionsRequest {
    username: string;
}

interface VerifyRegistrationRequest {
    username: string;
    credential: RegistrationResponseJSON;
}

interface LoginRequest {
    username: string;
    password: string;
}

// Registration routes
app.post('/api/auth/registration-options', async (req, res) => {
    try {
        const { username }: RegistrationOptionsRequest = req.body;

        const options = await generateRegistrationOptions({
            rpName,
            rpID,
            userName: username,
            attestationType: 'none',
            authenticatorSelection: {
                userVerification: 'preferred',
                residentKey: 'preferred',
            },
        });

        req.session.currentChallenge = options.challenge;
        res.json(options);
    } catch (error) {
        res.status(500).json({
            error: 'Internal server error'
        });
    }
});

app.post('/api/auth/verify-registration', async (req, res) => {
    const { username, credential }: VerifyRegistrationRequest = req.body;

    try {
        if (req.session.currentChallenge === undefined) {
            throw new Error('Session expired');
        }

        const verification = await verifyRegistrationResponse({
            response: credential as RegistrationResponseJSON,
            expectedChallenge: req.session.currentChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });

        if (verification.registrationInfo === undefined) {
            throw new Error('No registration information returned');
        }

        const { id: credentialID, publicKey: credentialPublicKey, counter } = verification.registrationInfo?.credential;

        const user = users.get(username);
        if (user === undefined) {
            throw new Error('User not found');
        }

        // Store user
        users.set(username, {
            ...user,
            devices: [{
                credentialID: Buffer.from(credentialID),
                credentialPublicKey: Buffer.from(credentialPublicKey),
                counter,
            }],
        });

        res.json({ verified: true });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password }: LoginRequest = req.body;
        const user = users.get(username);

        if (!user || user.password !== password) {
            res.status(401).json({ error: 'Invalid credentials' });
        } else {
            req.session.username = username;
            res.json({ success: true });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            error: 'Internal server error'
        });
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});