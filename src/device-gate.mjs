import { requireDeviceProof } from './device-auth.mjs';

// Always enforced in this candidate. Deployment follows registry bootstrap approval.
// There is deliberately no environment switch or token-kind exception.
export async function guardDeviceRequest(req, res, identity, authorization, config) {
  try {
    await requireDeviceProof(req, { identity, authorization, config });
    return true;
  } catch (error) {
    const recognized = Number.isInteger(error?.status) && error.status >= 400 && error.status <= 599
      && /^DEVICE_[A-Z0-9_]+$/u.test(error?.code ?? '');
    res.status(recognized ? error.status : 503).json({
      error: recognized ? error.code : 'DEVICE_VERIFICATION_UNAVAILABLE',
    });
    return false;
  }
}
