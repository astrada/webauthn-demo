import React, { useState } from 'react';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import './WebAuthnLogin.css';

interface LoginState {
    username: string;
    password: string;
    loading: boolean;
    error: string | null;
    isFirstFactorComplete: boolean;
    isRegistered: boolean;
}

const WebAuthnLogin: React.FC = () => {
    const [state, setState] = useState<LoginState>({
        username: '',
        password: '',
        loading: false,
        error: null,
        isFirstFactorComplete: false,
        isRegistered: false,
    });

    const handleFirstFactor = async (e: React.FormEvent) => {
        e.preventDefault();
        setState(prev => ({ ...prev, loading: true, error: null }));

        try {
            // First factor authentication (username/password)
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: state.username,
                    password: state.password,
                }),
            });

            if (!response.ok) throw new Error('Invalid credentials');

            setState(prev => ({ ...prev, isFirstFactorComplete: true }));
        } catch (error) {
            setState(prev => ({
                ...prev,
                error: error instanceof Error ? error.message : 'Authentication failed'
            }));
        } finally {
            setState(prev => ({ ...prev, loading: false }));
        }
    };

    const handleWebAuthn = async () => {
        setState(prev => ({ ...prev, loading: true, error: null }));

        try {
            // Get challenge from server
            const optionsResponse = await fetch('/api/auth/webauthn/generate-challenge');
            const options = await optionsResponse.json();

            // Start WebAuthn authentication
            const authResponse = await startAuthentication({optionsJSON: options});

            // Verify with server
            const verificationResponse = await fetch('/api/auth/webauthn/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(authResponse),
            });

            if (!verificationResponse.ok) throw new Error('WebAuthn verification failed');

            // Handle successful login
            alert('Successfully authenticated with WebAuthn');
        } catch (error) {
            setState(prev => ({
                ...prev,
                error: error instanceof Error ? error.message : 'WebAuthn authentication failed'
            }));
        } finally {
            setState(prev => ({ ...prev, loading: false }));
        }
    };

    const handleRegistration = async () => {
        setState(prev => ({ ...prev, loading: true, error: null }));

        try {
            // 1. Get registration options from server
            const optionsRes = await fetch('/api/auth/registration-options', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: state.username }),
            });

            if (!optionsRes.ok) {
                throw new Error('Failed to get registration options');
            }

            const options = await optionsRes.json();

            // 2. Start WebAuthn registration
            const credential = await startRegistration({ optionsJSON: options});

            // 3. Verify registration with server
            const verificationRes = await fetch('/api/auth/verify-registration', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: state.username,
                    credential
                }),
            });

            if (!verificationRes.ok) {
                throw new Error('Failed to verify registration');
            }

            // 4. Update registration state
            setState(prev => ({ ...prev, isRegistered: true }));

        } catch (error) {
            setState(prev => ({
                ...prev,
                error: error instanceof Error ? error.message : 'WebAuthn registration failed'
            }));
        } finally {
            setState(prev => ({ ...prev, loading: false }));
        }
    };

    return (
        <div className="login-container">
            {!state.isFirstFactorComplete ? (
                <form onSubmit={handleFirstFactor}>
                    <input
                        type="text"
                        placeholder="Username"
                        value={state.username}
                        onChange={e => setState(prev => ({ ...prev, username: e.target.value }))}
                    />
                    <input
                        type="password"
                        placeholder="Password"
                        value={state.password}
                        onChange={e => setState(prev => ({ ...prev, password: e.target.value }))}
                    />
                    <button type="submit" disabled={state.loading}>
                        {state.loading ? 'Loading...' : 'Continue'}
                    </button>
                    {!state.isRegistered && (
                        <button
                            type="button"
                            onClick={handleRegistration}
                            disabled={state.loading || !state.username}
                        >
                            {state.loading ? 'Registering...' : 'Register Security Key'}
                        </button>
                    )}
                    {state.error && <div className="error">{state.error}</div>}
                </form>
            ) : (
                <div>
                    <p>Complete authentication with your security key </p>
                    < button onClick={handleWebAuthn} disabled={state.loading} >
                        {state.loading ? 'Authenticating...' : 'Use Security Key'}
                    </button>
                </div>
            )}
            {state.error && <p className="error" > {state.error} </p>}
        </div>
    );
};

export default WebAuthnLogin;