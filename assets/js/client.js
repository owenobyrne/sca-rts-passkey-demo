/**
 * Browser-side WebAuthn calls. Two authorisation paths are offered:
 *
 *  1. Secure Payment Confirmation (SPC) — the browser itself renders the
 *     amount and payee in a dialog the page cannot style or suppress, and
 *     signs them into clientDataJSON. This is what the WebAuthn "payment"
 *     extension actually is; there is no `extensions.payment` dictionary on
 *     navigator.credentials.get(). Chromium only, for now.
 *  2. Plain navigator.credentials.get() — the page is responsible for showing
 *     the amount and payee before the prompt (RTS Art. 5(1)(b)).
 */

import { bytes } from './util.js';

export async function probeEnvironment() {
  const result = {
    secureContext: window.isSecureContext,
    origin: location.origin,
    rpId: location.hostname,
    webauthn: typeof window.PublicKeyCredential === 'function',
    platformAuthenticator: false,
    conditionalMediation: false,
    spc: false,
  };

  if (result.webauthn) {
    try {
      result.platformAuthenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      result.platformAuthenticator = false;
    }
    try {
      result.conditionalMediation = (await PublicKeyCredential.isConditionalMediationAvailable?.()) ?? false;
    } catch {
      result.conditionalMediation = false;
    }
  }

  if (typeof window.PaymentRequest === 'function') {
    try {
      const probe = new PaymentRequest(
        [{ supportedMethods: 'secure-payment-confirmation', data: {
          credentialIds: [new Uint8Array([1])],
          challenge: new Uint8Array(32),
          instrument: { displayName: 'probe', icon: new URL('assets/img/instrument.png', location.href).href },
          payeeName: 'probe',
          rpId: location.hostname,
          timeout: 60000,
        } }],
        { total: { label: 'probe', amount: { currency: 'EUR', value: '0.01' } } },
      );
      result.spc = await probe.canMakePayment();
    } catch {
      result.spc = false;
    }
  }

  return result;
}

export async function createPasskey(options) {
  const credential = await navigator.credentials.create({ publicKey: options });
  if (!credential) throw new Error('The authenticator returned no credential.');
  return credential;
}

/** Standard assertion. userVerification is "required" — SCA needs two elements. */
export async function authorisePlain({ challengeBytes, allowCredentials, rpId, timeout }) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: bytes(challengeBytes),
      allowCredentials,
      rpId,
      userVerification: 'required',
      timeout,
    },
  });
  if (!assertion) throw new Error('The authenticator returned no assertion.');
  return { assertion, method: 'webauthn.get' };
}

/**
 * Secure Payment Confirmation. The amount and payee passed here are rendered
 * by the browser and end up inside the signed clientDataJSON, which makes the
 * visual confirmation part of the cryptographic evidence rather than a promise
 * the web page makes.
 */
export async function authoriseWithSpc({
  challengeBytes,
  credentialIds,
  rpId,
  payeeName,
  amount,
  currency,
  instrumentLabel,
  timeout = 120000,
}) {
  if (typeof window.PaymentRequest !== 'function') throw new Error('PaymentRequest is unavailable in this browser.');

  const request = new PaymentRequest(
    [
      {
        supportedMethods: 'secure-payment-confirmation',
        data: {
          credentialIds: credentialIds.map((id) => bytes(id)),
          challenge: bytes(challengeBytes),
          instrument: {
            displayName: instrumentLabel,
            icon: new URL('assets/img/instrument.png', location.href).href,
            iconMustBeShown: false,
          },
          payeeName,
          rpId,
          timeout,
        },
      },
    ],
    { total: { label: 'Total', amount: { currency, value: amount } } },
  );

  const response = await request.show();
  await response.complete('success');
  return { assertion: response.details, method: 'payment.get' };
}

/** Normalise a PublicKeyCredential into the plain shape the server verifies. */
export function serialiseAssertion(credential) {
  return {
    rawId: credential.rawId,
    id: credential.id,
    response: {
      clientDataJSON: credential.response.clientDataJSON,
      authenticatorData: credential.response.authenticatorData,
      signature: credential.response.signature,
      userHandle: credential.response.userHandle,
    },
  };
}

export function friendlyWebauthnError(error) {
  const name = error?.name ?? '';
  switch (name) {
    case 'NotAllowedError':
      return 'The authorisation was cancelled, or timed out, or the browser blocked it (a passkey prompt needs a user gesture on a secure origin).';
    case 'InvalidStateError':
      return 'A passkey for this site already exists on that authenticator.';
    case 'SecurityError':
      return `The relying party ID does not match this origin (${location.origin}). Passkeys only work over HTTPS or on localhost.`;
    case 'NotSupportedError':
      return 'No requested algorithm is supported by the available authenticator.';
    case 'AbortError':
      return 'The request was aborted.';
    default:
      return error?.message ? `${name || 'Error'}: ${error.message}` : String(error);
  }
}
