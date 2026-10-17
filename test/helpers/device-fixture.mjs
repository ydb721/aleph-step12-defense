// Test-only authenticators and storage. No keys or fixtures are persisted.
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { DeviceError, sessionHash } from '../../src/device-auth.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest();
const base64url = bytes => Buffer.from(bytes).toString('base64url');

export function createAuthenticator(rpID, origin) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credentialIdBytes = randomBytes(32);
  const credentialId = base64url(credentialIdBytes);
  const cose = Buffer.from(isoCBOR.encode(new Map([
    [1, 2], [3, -7], [-1, 1],
    [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')],
  ])));
  let authenticationCounter = 0;

  function clientData(options, overrides, type) {
    return Buffer.from(JSON.stringify({ type: overrides.type ?? type,
      challenge: overrides.challenge ?? options.challenge,
      origin: overrides.origin ?? origin, crossOrigin: false }));
  }
  function authenticatorData(overrides, registration) {
    let flags = (overrides.up === false ? 0 : 1) | (overrides.uv === false ? 0 : 4)
      | (overrides.multiDevice ? 8 : 0) | (overrides.backedUp ? 16 : 0) | (registration ? 64 : 0);
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(overrides.counter ?? 0);
    const parts = [sha256(overrides.rpID ?? rpID), Buffer.from([flags]), counter];
    if (registration) {
      const length = Buffer.alloc(2);
      length.writeUInt16BE(credentialIdBytes.length);
      parts.push(Buffer.alloc(16), length, credentialIdBytes, cose);
    }
    return Buffer.concat(parts);
  }
  return {
    credential: { credentialId, publicKey: base64url(cose), counter: 0, transports: ['usb'],
      deviceType: 'singleDevice', backedUp: false, publicKeySha256: sha256(cose).toString('hex') },
    responseRegistration(options, overrides = {}) {
      const authData = authenticatorData(overrides, true);
      const attestation = isoCBOR.encode(new Map([
        ['fmt', 'none'], ['attStmt', new Map()], ['authData', authData],
      ]));
      return { id: credentialId, rawId: credentialId, type: 'public-key',
        authenticatorAttachment: 'cross-platform', clientExtensionResults: {},
        response: { clientDataJSON: base64url(clientData(options, overrides, 'webauthn.create')),
          attestationObject: base64url(attestation), transports: ['usb'] } };
    },
    responseAuthentication(options, overrides = {}) {
      const counter = overrides.counter ?? authenticationCounter + 1;
      authenticationCounter = Math.max(authenticationCounter, counter);
      const client = clientData(options, overrides, 'webauthn.get');
      const authData = authenticatorData({ ...overrides, counter }, false);
      return { id: credentialId, rawId: credentialId, type: 'public-key',
        authenticatorAttachment: 'cross-platform', clientExtensionResults: {},
        response: { clientDataJSON: base64url(client), authenticatorData: base64url(authData),
          signature: base64url(sign('sha256', Buffer.concat([authData, sha256(client)]), privateKey)),
          userHandle: null } };
    },
  };
}

export function proofHeader(nonceId, assertion) {
  return base64url(Buffer.from(JSON.stringify({ nonceId, assertion })));
}

// Explicit in-memory model for unit tests; this is not a database or its E2E test.
export function createMemoryDeviceStore({ identity, authorization, devices: initial = [] }) {
  const ownerId = identity.userId.toLowerCase();
  const tokenHash = sessionHash(authorization);
  const devices = new Map();
  const challenges = new Map();
  const calls = [];
  const copy = value => structuredClone(value);
  const reject = code => { throw new DeviceError(403, code); };
  function ownedDevice(credentialId) {
    const device = [...devices.values()].find(value => value.credentialId === credentialId && value.ownerId === ownerId);
    if (!device) reject('DEVICE_REGISTRATION_REQUIRED');
    return device;
  }
  function liveChallenge(nonceId, purpose) {
    const challenge = challenges.get(nonceId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.sessionHash !== tokenHash
        || purpose && challenge.purpose !== purpose) reject('DEVICE_REQUEST_MISMATCH');
    if (challenge.consumedAt) reject('DEVICE_NONCE_REUSED');
    if (Date.parse(challenge.expiresAt) <= Date.now()) reject('DEVICE_CHALLENGE_EXPIRED');
    return challenge;
  }
  const store = {
    devices, challenges, calls,
    addDevice(credential, state = 'approved') {
      const device = { ...copy(credential), id: randomUUID(), ownerId, state,
        createdAt: new Date().toISOString() };
      devices.set(device.id, device);
      return copy(device);
    },
    async action(action, payload = {}) {
      calls.push(action);
      if (action === 'list') return { devices: copy([...devices.values()].filter(device => device.ownerId === ownerId)) };
      if (action === 'get_credential') return { device: copy(ownedDevice(payload.credentialId)) };
      if (action === 'get_challenge') {
        const challenge = challenges.get(payload.nonceId);
        if (!challenge || challenge.ownerId !== ownerId || challenge.sessionHash !== tokenHash) reject('DEVICE_REQUEST_MISMATCH');
        return { challenge: copy(challenge) };
      }
      if (action === 'challenge') {
        if (challenges.has(payload.id)) reject('DEVICE_NONCE_REUSED');
        if (payload.purpose === 'request' && ownedDevice(payload.credentialId).state !== 'approved') reject('DEVICE_NOT_APPROVED');
        const challenge = { ...copy(payload), ownerId, sessionHash: tokenHash,
          expiresAt: new Date(Date.now() + 90000).toISOString(), consumedAt: null };
        challenges.set(challenge.id, challenge);
        return { challenge: copy(challenge) };
      }
      if (action === 'register') {
        const challenge = liveChallenge(payload.nonceId, 'registration');
        if ([...devices.values()].some(device => device.credentialId === payload.credentialId)) reject('DEVICE_CREDENTIAL_EXISTS');
        const credential = { ...copy(payload) };
        delete credential.nonceId;
        credential.publicKeySha256 = sha256(Buffer.from(credential.publicKey, 'base64url')).toString('hex');
        const device = store.addDevice(credential, 'pending');
        challenge.consumedAt = new Date().toISOString();
        return { device };
      }
      if (action === 'consume') {
        store.beforeConsume?.(payload);
        const device = ownedDevice(payload.credentialId);
        if (device.state !== 'approved') reject('DEVICE_NOT_APPROVED');
        const challenge = liveChallenge(payload.nonceId, 'request');
        if (challenge.credentialId !== payload.credentialId
            || JSON.stringify(challenge.binding) !== JSON.stringify(payload.binding)) reject('DEVICE_REQUEST_MISMATCH');
        if (device.counter !== payload.expectedCounter
            || !(payload.newCounter === 0 && payload.expectedCounter === 0 || payload.newCounter > payload.expectedCounter)) reject('DEVICE_COUNTER_CHANGED');
        device.counter = payload.newCounter;
        challenge.consumedAt = new Date().toISOString();
        return { device: copy(device) };
      }
      if (action === 'decision') {
        const actor = devices.get(payload.actorDeviceId);
        const target = devices.get(payload.targetDeviceId);
        if (!actor || actor.ownerId !== ownerId || actor.state !== 'approved') reject('DEVICE_NOT_APPROVED');
        if (!target || target.ownerId !== ownerId) reject('DEVICE_REGISTRATION_REQUIRED');
        if (actor.id === target.id && payload.decision !== 'revoked') reject('DEVICE_SELF_APPROVAL_FORBIDDEN');
        if (!(target.state === 'pending' && ['approved', 'rejected'].includes(payload.decision)
            || target.state === 'approved' && payload.decision === 'revoked')) reject('DEVICE_INVALID_DECISION');
        target.state = payload.decision;
        return { device: copy(target) };
      }
      throw new Error('Unsupported test store action');
    },
  };
  initial.forEach(device => store.addDevice(device));
  return store;
}
