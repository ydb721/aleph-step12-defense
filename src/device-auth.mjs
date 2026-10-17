import { createHash } from 'node:crypto';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { readVerifiedRequest, requestTarget } from './device-request.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RPC_ERRORS = new Set([
  'DEVICE_NOT_APPROVED', 'DEVICE_CHALLENGE_EXPIRED', 'DEVICE_NONCE_REUSED',
  'DEVICE_REQUEST_MISMATCH', 'DEVICE_COUNTER_CHANGED', 'DEVICE_REGISTRATION_REQUIRED',
  'DEVICE_REGISTRATION_UNSUPPORTED', 'DEVICE_CREDENTIAL_EXISTS', 'DEVICE_LIMIT_REACHED',
  'DEVICE_INVALID_ACTION', 'DEVICE_INVALID_INPUT', 'DEVICE_INVALID_DECISION',
  'DEVICE_SELF_APPROVAL_FORBIDDEN',
]);

export class DeviceError extends Error {
  constructor(status, code) {
    super(code);
    this.name = 'DeviceError';
    this.status = status;
    this.code = code;
  }
}

export function deviceRP(config) {
  let app;
  try { app = new URL(config?.publicAppUrl); } catch { throw new DeviceError(503, 'DEVICE_CONFIGURATION_REQUIRED'); }
  if (app.protocol !== 'https:' || app.username || app.password || app.port
      || app.pathname !== '/' || app.search || app.hash) {
    throw new DeviceError(503, 'DEVICE_CONFIGURATION_REQUIRED');
  }
  return { origin: app.origin, rpID: app.hostname };
}

export function requestAuthorization(req) {
  const bearer = req.headers?.authorization;
  if (bearer !== undefined) return typeof bearer === 'string' ? bearer : undefined;
  const cookie = String(req.headers?.cookie || '').split(';').map(part => part.trim())
    .find(part => part.startsWith('__Host-byteback-access='));
  if (!cookie) return undefined;
  try { return 'Bearer ' + decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1)); }
  catch { return undefined; }
}

export function sessionHash(authorization) {
  const match = typeof authorization === 'string' && /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u.exec(authorization);
  if (!match || authorization.length > 8192) throw new DeviceError(401, 'AUTH_REQUIRED');
  return createHash('sha256').update(match[1], 'utf8').digest('hex');
}

function verifiedUser(identity) {
  if (!identity || typeof identity.userId !== 'string' || !UUID.test(identity.userId)) {
    throw new DeviceError(401, 'AUTH_REQUIRED');
  }
  return identity.userId.toLowerCase();
}

export function descriptorBinding(descriptor, identity, authorization) {
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)
      || !['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].includes(descriptor.method)
      || typeof descriptor.path !== 'string' || !descriptor.path.startsWith('/api/')
      || descriptor.path.length > 4096 || /[?\u0000-\u0020\u007f#\\]/u.test(descriptor.path)
      || typeof descriptor.query !== 'string' || descriptor.query.length > 4096
      || descriptor.query !== '' && !descriptor.query.startsWith('?')
      || /[\u0000-\u0020\u007f#\\]/u.test(descriptor.query)
      || typeof descriptor.bodySha256 !== 'string' || !SHA256.test(descriptor.bodySha256)) {
    throw new DeviceError(400, 'DEVICE_INVALID_REQUEST');
  }
  return {
    method: descriptor.method, path: descriptor.path, query: descriptor.query,
    bodySha256: descriptor.bodySha256, userId: verifiedUser(identity),
    sessionHash: sessionHash(authorization),
  };
}

export async function requestBinding(req, identity, authorization) {
  const bytes = await readVerifiedRequest(req);
  return descriptorBinding({ method: req.method, ...requestTarget(req),
    bodySha256: createHash('sha256').update(bytes).digest('hex') }, identity, authorization);
}

export function createDeviceStore({ identity, authorization, config,
  supabaseUrl = process.env.SUPABASE_URL,
  secretKey = process.env.SUPABASE_SECRET_KEY, fetchImpl = fetch } = {}) {
  const userId = verifiedUser(identity);
  const tokenHash = sessionHash(authorization);
  let url;
  let issuer;
  try {
    url = new URL(supabaseUrl);
    issuer = new URL(config?.identityProvider?.issuer);
  } catch { throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE'); }
  if (url.protocol !== 'https:' || url.origin !== issuer.origin || url.username || url.password
      || typeof secretKey !== 'string' || !secretKey.trim() || secretKey !== secretKey.trim()
      || typeof fetchImpl !== 'function') {
    throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');
  }
  const endpoint = new URL('/rest/v1/rpc/byteback_device_action', url.origin);
  return {
    async action(action, payload = {}) {
      let response;
      let result;
      try {
        response = await fetchImpl(endpoint, {
          method: 'POST',
          headers: { apikey: secretKey, Authorization: 'Bearer ' + secretKey,
            'Content-Type': 'application/json' },
          body: JSON.stringify({ p_action: action, p_user: userId,
            p_session_hash: tokenHash, p_payload: payload }),
          signal: AbortSignal.timeout(7000),
        });
        result = await response.json();
      } catch { throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE'); }
      if (!response.ok) {
        const code = result?.message;
        if (RPC_ERRORS.has(code)) {
          const status = code === 'DEVICE_CREDENTIAL_EXISTS' ? 409
            : code === 'DEVICE_LIMIT_REACHED' ? 429
              : code.startsWith('DEVICE_INVALID_') ? 400 : 403;
          throw new DeviceError(status, code);
        }
        throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');
      }
      if (!result || typeof result !== 'object' || Array.isArray(result)) {
        throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');
      }
      return result;
    },
  };
}

export function publicDevice(device) {
  return { id: device.id, credentialId: device.credentialId, state: device.state,
    fingerprint: device.publicKeySha256, createdAt: device.createdAt };
}

export function requireApprovedCredential(device, identity) {
  if (!device || typeof device.ownerId !== 'string'
      || device.ownerId.toLowerCase() !== verifiedUser(identity) || device.state !== 'approved') {
    throw new DeviceError(403, 'DEVICE_NOT_APPROVED');
  }
  if (device.deviceType !== 'singleDevice' || device.backedUp !== false) {
    throw new DeviceError(403, 'DEVICE_REGISTRATION_UNSUPPORTED');
  }
  if (typeof device.id !== 'string' || !UUID.test(device.id)
      || typeof device.credentialId !== 'string' || !BASE64URL.test(device.credentialId)
      || typeof device.publicKey !== 'string' || !BASE64URL.test(device.publicKey)
      || !Number.isInteger(device.counter) || device.counter < 0 || device.counter > 4294967295) {
    throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');
  }
  const keyBytes = Buffer.from(device.publicKey, 'base64url');
  if (!keyBytes.length || keyBytes.length > 4096 || keyBytes.toString('base64url') !== device.publicKey) {
    throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');
  }
  return device;
}

export function requireLiveChallenge(challenge, { identity, authorization, purpose, nonceId }) {
  if (!challenge || challenge.id !== nonceId || challenge.purpose !== purpose
      || typeof challenge.ownerId !== 'string'
      || challenge.ownerId.toLowerCase() !== verifiedUser(identity)
      || challenge.sessionHash !== sessionHash(authorization)) {
    throw new DeviceError(403, 'DEVICE_REQUEST_MISMATCH');
  }
  if (challenge.consumedAt !== null && challenge.consumedAt !== undefined) {
    throw new DeviceError(403, 'DEVICE_NONCE_REUSED');
  }
  if (!Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.now()) {
    throw new DeviceError(403, 'DEVICE_CHALLENGE_EXPIRED');
  }
  if (typeof challenge.challenge !== 'string' || !BASE64URL.test(challenge.challenge)
      || challenge.challenge.length < 32 || challenge.challenge.length > 256) {
    throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');
  }
  return challenge;
}

function readProof(req) {
  const encoded = req.headers?.['x-byteback-proof'];
  if (encoded === undefined) throw new DeviceError(403, 'DEVICE_SIGNATURE_REQUIRED');
  if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > 12000 || !BASE64URL.test(encoded)) {
    throw new DeviceError(403, 'DEVICE_INVALID_PROOF');
  }
  let proof;
  try {
    const decoded = Buffer.from(encoded, 'base64url');
    if (decoded.toString('base64url') !== encoded) throw new Error();
    proof = JSON.parse(decoded.toString('utf8'));
  } catch { throw new DeviceError(403, 'DEVICE_INVALID_PROOF'); }
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)
      || Object.keys(proof).length !== 2 || typeof proof.nonceId !== 'string'
      || !UUID.test(proof.nonceId) || !proof.assertion || typeof proof.assertion !== 'object'
      || Array.isArray(proof.assertion) || typeof proof.assertion.id !== 'string'
      || proof.assertion.id.length > 2048 || !BASE64URL.test(proof.assertion.id)) {
    throw new DeviceError(403, 'DEVICE_INVALID_PROOF');
  }
  return proof;
}

function sameBinding(expected, actual) {
  return expected && typeof expected === 'object' && !Array.isArray(expected)
    && Object.keys(expected).length === Object.keys(actual).length
    && Object.keys(actual).every(key => expected[key] === actual[key]);
}

export async function requireDeviceProof(req, { identity, authorization, config, store } = {}) {
  const proof = readProof(req);
  const rp = deviceRP(config);
  const binding = await requestBinding(req, identity, authorization);
  const db = store ?? createDeviceStore({ identity, authorization, config });
  if (typeof db?.action !== 'function') throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');
  const { challenge } = await db.action('get_challenge', { nonceId: proof.nonceId });
  requireLiveChallenge(challenge, { identity, authorization, purpose: 'request', nonceId: proof.nonceId });
  if (challenge.credentialId !== proof.assertion.id) {
    throw new DeviceError(403, 'DEVICE_REQUEST_MISMATCH');
  }
  if (!sameBinding(challenge.binding, binding)) {
    throw new DeviceError(403, 'DEVICE_REQUEST_MISMATCH');
  }
  const { device: stored } = await db.action('get_credential', { credentialId: proof.assertion.id });
  const credential = requireApprovedCredential(stored, identity);
  if (credential.credentialId !== proof.assertion.id) throw new DeviceError(403, 'DEVICE_REQUEST_MISMATCH');
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: proof.assertion,
      expectedChallenge: challenge.challenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpID,
      requireUserVerification: true,
      credential: { id: credential.credentialId,
        publicKey: new Uint8Array(Buffer.from(credential.publicKey, 'base64url')),
        counter: credential.counter, transports: credential.transports },
    });
  } catch { throw new DeviceError(403, 'DEVICE_SIGNATURE_INVALID'); }
  const info = verification.authenticationInfo;
  if (!verification.verified || !info?.userVerified
      || info.credentialDeviceType !== 'singleDevice' || info.credentialBackedUp !== false) {
    throw new DeviceError(403, 'DEVICE_SIGNATURE_INVALID');
  }
  const verifiedBinding = await requestBinding(req, identity, authorization);
  if (!sameBinding(challenge.binding, verifiedBinding) || !sameBinding(binding, verifiedBinding)) {
    throw new DeviceError(403, 'DEVICE_REQUEST_MISMATCH');
  }
  // Verification alone never consumes a challenge. The database atomically
  // rechecks approval, nonce freshness, request binding and the old counter.
  const { device } = await db.action('consume', {
    nonceId: proof.nonceId, credentialId: credential.credentialId,
    expectedCounter: credential.counter, newCounter: info.newCounter, binding: verifiedBinding,
  });
  const consumedBinding = await requestBinding(req, identity, authorization);
  if (!sameBinding(challenge.binding, consumedBinding) || !sameBinding(verifiedBinding, consumedBinding)) {
    throw new DeviceError(403, 'DEVICE_REQUEST_MISMATCH');
  }
  requireApprovedCredential(device, identity);
  if (device.id !== credential.id || device.credentialId !== credential.credentialId) {
    throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');
  }
  return { deviceId: device.id, credentialId: device.credentialId };
}
