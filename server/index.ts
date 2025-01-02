import express from "express";
import session from "express-session";
import morgan from "morgan";
import https from "https";
import fs from "fs";
import path from "path";
import {
  AuthenticationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { RegistrationResponseJSON } from "@simplewebauthn/typescript-types";

const app = express();
const rpName = "WebAuthn Demo";
const rpID = "localhost";
const origin = `https://${rpID}:5173`;

// In-memory user store (replace with database in production)
const users = new Map<
  string,
  {
    id: string;
    username: string;
    password: string;
    devices: Array<{
      credentialID: Buffer;
      credentialPublicKey: Buffer;
      counter: number;
    }>;
  }
>();

users.set("test", {
  id: "1",
  username: "test",
  password: "test",
  devices: [],
});

app.use(express.json());
app.use(
  session({
    secret: "webauthn-demo-secret-key",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(morgan("dev"));

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
app.post("/api/auth/registration-options", async (req, res) => {
  try {
    const { username }: RegistrationOptionsRequest = req.body;

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: username,
      attestationType: "none",
      authenticatorSelection: {
        userVerification: "preferred",
        residentKey: "preferred",
      },
    });

    req.session.currentChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.post("/api/auth/verify-registration", async (req, res) => {
  const { username, credential }: VerifyRegistrationRequest = req.body;

  try {
    if (req.session.currentChallenge === undefined) {
      throw new Error("Session expired");
    }

    const verification = await verifyRegistrationResponse({
      response: credential as RegistrationResponseJSON,
      expectedChallenge: req.session.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.registrationInfo === undefined) {
      throw new Error("No registration information returned");
    }

    const {
      id: credentialID,
      publicKey: credentialPublicKey,
      counter,
    } = verification.registrationInfo?.credential;

    const user = users.get(username);
    if (user === undefined) {
      throw new Error("User not found");
    }

    // Store user
    users.set(username, {
      ...user,
      devices: [
        {
          credentialID: Buffer.from(credentialID),
          credentialPublicKey: Buffer.from(credentialPublicKey),
          counter,
        },
      ],
    });

    res.json({ verified: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get("/api/auth/webauthn/generate-challenge", async (req, res) => {
  try {
    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: "preferred",
    });

    req.session.currentChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.post("/api/auth/webauthn/verify", async (req, res) => {
  if (req.session.currentChallenge === undefined) {
    res.status(400).json({
      error: "Session expired",
    });
    return;
  }

  if (req.session.username === undefined) {
    res.status(400).json({
      error: "Not logged in",
    });
    return;
  }

  const user = users.get(req.session.username);
  if (user === undefined) {
    res.status(400).json({
      error: "User not found",
    });
    return;
  }

  const device = user.devices[0];
  if (device === undefined) {
    res.status(400).json({
      error: "No device found",
    });
    return;
  }

  try {
    const authResponse: AuthenticationResponseJSON = req.body;

    const verifiedAuthenticationResponse = await verifyAuthenticationResponse({
      response: authResponse,
      expectedChallenge: req.session.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: device.credentialID.toString(),
        publicKey: device.credentialPublicKey,
        counter: device.counter,
      },
    });

    res.json(verifiedAuthenticationResponse);
  } catch (error) {
    res.status(500).json({
      error: "Internal server error",
    });
  }
});

// Authentication routes
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password }: LoginRequest = req.body;
    const user = users.get(username);

    if (!user || user.password !== password) {
      res.status(401).json({ error: "Invalid credentials" });
    } else {
      req.session.username = username;
      res.json({ success: true });
    }
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      error: "Internal server error",
    });
  }
});

const dirname = path.resolve();
const options = {
  key: fs.readFileSync(path.join(dirname, "server/localhost-key.pem")),
  cert: fs.readFileSync(path.join(dirname, "server/localhost.pem")),
};
const server = https.createServer(options, app);
server.listen(3000, () => {
  console.log("Server running on port 3000");
});
