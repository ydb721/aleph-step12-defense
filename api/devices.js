import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { generateAuthenticationOptions, generateRegistrationOptions,
  verifyRegistrationResponse } from '@simplewebauthn/server';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { readVerifiedRequest } from '../src/device-request.mjs';
import { DeviceError, createDeviceStore, descriptorBinding, deviceRP, publicDevice,
  requestAuthorization, requireApprovedCredential, requireDeviceProof,
  requireLiveChallenge } from '../src/device-auth.mjs';

const require = createRequire(import.meta.url);
const projectConfig = require('../aleph.config.json');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const CREDENTIAL = /^[A-Za-z0-9_-]{1,2048}$/u;

function deviceList(result, identity) {
  if (!Array.isArray(result?.devices) || result.devices.some(device => !device
      || typeof device.ownerId !== 'string'
      || device.ownerId.toLowerCase() !== identity.userId.toLowerCase())) {
    throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');
  }
  return result.devices;
}

function sameOriginPost(req, origin) {
  if (req.headers?.origin !== undefined && req.headers.origin !== origin
      || req.headers?.['sec-fetch-site'] === 'cross-site'
      || !req.headers?.authorization && req.headers?.origin !== origin) {
    throw new DeviceError(403, 'ORIGIN_REJECTED');
  }
}

// Dependency injection is for isolated verification. The production handler
// below always uses the existing login verifier and the private database RPC.
export function createDeviceHandler({ config = projectConfig, verifyLogin, store } = {}) {
  let loginVerifier = verifyLogin;
  return async function handleDevices(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    if (!['GET', 'POST'].includes(req.method)) {
      res.setHeader('Allow', 'GET, POST');
      return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    try {
      const rp = deviceRP(config);
      if (!loginVerifier) {
        try {
          loginVerifier = createLoginVerifier({ config,
            supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
        } catch { throw new DeviceError(503, 'DEVICE_CONFIGURATION_REQUIRED'); }
      }
      const authorization = requestAuthorization(req);
      const identity = await loginVerifier(authorization);
      if (!identity) return res.status(401).json({ error: 'AUTH_REQUIRED' });
      if (req.method === 'POST') sameOriginPost(req, rp.origin);
      const db = store ?? createDeviceStore({ identity, authorization, config });
      if (typeof db?.action !== 'function') throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');

      if (req.method === 'GET') {
        const devices = deviceList(await db.action('list'), identity);
        return res.status(200).json({ devices: devices.map(publicDevice) });
      }

      await readVerifiedRequest(req);
      let incoming;
      try {
        if (typeof req.body !== 'string') throw new Error();
        incoming = JSON.parse(req.body);
      } catch { throw new DeviceError(400, 'DEVICE_INVALID_REQUEST'); }
      if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
        throw new DeviceError(400, 'DEVICE_INVALID_REQUEST');
      }

      if (incoming.action === 'registration-options') {
        const devices = deviceList(await db.action('list'), identity);
        const userBytes = createHash('sha256').update(identity.kind + ':' + identity.userId.toLowerCase()).digest();
        const userAlias = 'member-' + userBytes.toString('hex').slice(0, 16);
        const options = await generateRegistrationOptions({
          rpName: 'Byteback', rpID: rp.rpID, userID: new Uint8Array(userBytes),
          userName: userAlias, userDisplayName: userAlias,
          attestationType: 'none', timeout: 90000,
          supportedAlgorithmIDs: [-7, -257],
          authenticatorSelection: { residentKey: 'discouraged', userVerification: 'required' },
          excludeCredentials: devices.map(device => ({ id: device.credentialId,
            transports: device.transports })),
        });
        const nonceId = randomUUID();
        const { challenge } = await db.action('challenge', { id: nonceId,
          challenge: options.challenge, purpose: 'registration', credentialId: null, binding: {} });
        requireLiveChallenge(challenge, { identity, authorization, purpose: 'registration', nonceId });
        return res.status(200).json({ nonceId, options });
      }

      if (incoming.action === 'registration-verify') {
        if (typeof incoming.nonceId !== 'string' || !UUID.test(incoming.nonceId)
            || !incoming.response || typeof incoming.response !== 'object'
            || Array.isArray(incoming.response)) {
          throw new DeviceError(400, 'DEVICE_INVALID_REQUEST');
        }
        const { challenge } = await db.action('get_challenge', { nonceId: incoming.nonceId });
        requireLiveChallenge(challenge, { identity, authorization,
          purpose: 'registration', nonceId: incoming.nonceId });
        let verification;
        try {
          verification = await verifyRegistrationResponse({ response: incoming.response,
            expectedChallenge: challenge.challenge, expectedOrigin: rp.origin,
            expectedRPID: rp.rpID, requireUserVerification: true,
            supportedAlgorithmIDs: [-7, -257] });
        } catch { throw new DeviceError(403, 'DEVICE_REGISTRATION_INVALID'); }
        const info = verification.registrationInfo;
        if (!verification.verified || !info?.userVerified) {
          throw new DeviceError(403, 'DEVICE_REGISTRATION_INVALID');
        }
        if (info.credentialDeviceType !== 'singleDevice' || info.credentialBackedUp !== false) {
          throw new DeviceError(403, 'DEVICE_REGISTRATION_UNSUPPORTED');
        }
        const credential = info.credential;
        const { device } = await db.action('register', {
          nonceId: incoming.nonceId, credentialId: credential.id,
          publicKey: Buffer.from(credential.publicKey).toString('base64url'),
          counter: credential.counter, transports: credential.transports ?? [],
          deviceType: info.credentialDeviceType, backedUp: info.credentialBackedUp,
        });
        if (!device || device.state !== 'pending' || device.credentialId !== credential.id
            || device.ownerId?.toLowerCase() !== identity.userId.toLowerCase()) {
          throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');
        }
        return res.status(201).json({ device: publicDevice(device) });
      }

      if (incoming.action === 'request-options') {
        if (typeof incoming.credentialId !== 'string' || !CREDENTIAL.test(incoming.credentialId)) {
          throw new DeviceError(400, 'DEVICE_INVALID_REQUEST');
        }
        const binding = descriptorBinding(incoming, identity, authorization);
        const { device: stored } = await db.action('get_credential', { credentialId: incoming.credentialId });
        const device = requireApprovedCredential(stored, identity);
        if (device.credentialId !== incoming.credentialId) throw new DeviceError(403, 'DEVICE_REQUEST_MISMATCH');
        const options = await generateAuthenticationOptions({ rpID: rp.rpID,
          userVerification: 'required', timeout: 90000,
          allowCredentials: [{ id: device.credentialId, transports: device.transports }] });
        const nonceId = randomUUID();
        const { challenge } = await db.action('challenge', { id: nonceId,
          challenge: options.challenge, purpose: 'request', credentialId: device.credentialId, binding });
        requireLiveChallenge(challenge, { identity, authorization, purpose: 'request', nonceId });
        return res.status(200).json({ nonceId, options });
      }

      if (incoming.action === 'decision') {
        if (typeof incoming.targetDeviceId !== 'string' || !UUID.test(incoming.targetDeviceId)
            || !['approved', 'rejected', 'revoked'].includes(incoming.decision)
            || typeof incoming.reason !== 'string' || incoming.reason.trim().length < 3
            || incoming.reason.length > 240) {
          throw new DeviceError(400, 'DEVICE_INVALID_DECISION');
        }
        const targetDeviceId = incoming.targetDeviceId.toLowerCase();
        const actor = await requireDeviceProof(req, { identity, authorization, config, store: db });
        const { device } = await db.action('decision', { actorDeviceId: actor.deviceId,
          targetDeviceId, decision: incoming.decision, reason: incoming.reason.trim() });
        if (!device || device.id !== targetDeviceId
            || device.ownerId?.toLowerCase() !== identity.userId.toLowerCase()) {
          throw new DeviceError(503, 'DEVICE_STORE_UNAVAILABLE');
        }
        return res.status(200).json({ device: publicDevice(device) });
      }
      throw new DeviceError(400, 'DEVICE_INVALID_ACTION');
    } catch (error) {
      const known = error instanceof DeviceError
        || typeof error?.code === 'string' && /^(?:DEVICE_|RAW_BODY_)/u.test(error.code)
          && Number.isInteger(error.status) && error.status >= 400 && error.status <= 599;
      return res.status(known ? error.status : 503)
        .json({ error: known ? error.code : 'DEVICE_STORE_UNAVAILABLE' });
    }
  };
}

export default createDeviceHandler();
