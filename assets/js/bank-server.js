/**
 * A *simulated* payment service provider back end.
 *
 * Everything in this file is the logic that must live on a real server: it
 * mints the dynamically linked challenge, keeps the authoritative copy of the
 * transaction, and verifies the WebAuthn assertion. It runs in the browser
 * only because GitHub Pages serves static files — see README.md. No key
 * material or decision made here would be trustworthy in production.
 */

import {
  b64uDecode,
  b64uEncode,
  bytes,
  bytesEqual,
  canonicalJson,
  concatBytes,
  randomBytes,
  sha256,
  textDecoder,
  textEncoder,
  nowIso,
} from './util.js';
import {
  ALG_LABELS,
  COSE_ALG,
  coseKeyToJwk,
  derToRawEcdsaSignature,
  formatAaguid,
  importParamsFor,
  parseAuthenticatorData,
} from './webauthn-codec.js';
import { decode as cborDecode } from './cbor.js';

const STORAGE_KEY = 'sca-rts-demo/bank-state/v1';
const STATE_VERSION = 2;
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // Art. 4(3)(b): authentication codes are short-lived.

const PASS = 'pass';
const FAIL = 'fail';
const SKIP = 'skip';
const WARN = 'warn';

function emptyState() {
  return {
    user: { id: b64uEncode(randomBytes(16)), name: 'owen.demo@example.eu', displayName: 'Owen O’Byrne' },
    credentials: {},
    // Art. 10 state: when SCA was last applied, and whether this customer has
    // ever authenticated on this channel.
    session: { signedInAt: null, lastScaAt: null, accessCount: 0 },
    beneficiaries: {},
    lowValueCounters: { amountEur: 0, count: 0 },
    ledger: [],
    seq: 0,
    version: STATE_VERSION,
  };
}

/**
 * Upgrade state written by an earlier version of the demo.
 *
 * Version 1 predates the three-scenario model: its ledger entries are payments
 * with no `kind` and no `subject`, and there is no session or beneficiary
 * state. Migrating beats discarding, because the customer's enrolled
 * credentials live in here too — and a stored shape the code cannot read must
 * never be able to stop the page from loading.
 */
function migrate(parsed) {
  const state = { ...emptyState(), ...parsed };
  if (parsed?.version === STATE_VERSION) return state;

  state.ledger = (Array.isArray(parsed?.ledger) ? parsed.ledger : []).map((entry) => {
    const subject = entry?.subject ?? entry?.transaction ?? {};
    const kind = entry?.kind ?? subject.type ?? (subject.payee || subject.amount ? 'payment' : 'unknown');
    return { ...entry, kind, subject: { ...subject, type: kind } };
  });
  state.version = STATE_VERSION;
  return state;
}

export class BankServer {
  constructor({ rpId, rpName, origin, log = () => {} }) {
    this.rpId = rpId;
    this.rpName = rpName;
    this.origin = origin;
    this.log = log;
    this.pending = new Map(); // challenge (base64url) -> authorisation context
    this.state = this.#load();
  }

  #load() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return emptyState();
      return migrate(JSON.parse(raw));
    } catch (error) {
      // Corrupt or unreadable state is not worth a broken page.
      this.log?.('warn', 'Stored demo state could not be read; starting fresh', String(error));
      return emptyState();
    }
  }

  #save() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.state));
    } catch (error) {
      this.log('warn', 'Could not persist server state to localStorage', { error: String(error) });
    }
  }

  reset() {
    this.pending.clear();
    this.state = emptyState();
    this.#save();
  }

  get user() {
    return this.state.user;
  }

  get credentials() {
    return Object.values(this.state.credentials);
  }

  get lowValueCounters() {
    return this.state.lowValueCounters;
  }

  // ---------------------------------------------------------------- enrolment

  /**
   * Options for navigator.credentials.create(). userVerification is "required":
   * under PSD2 the passkey has to deliver two independent elements — possession
   * of the authenticator plus inherence (biometric) or knowledge (device PIN) —
   * and only a set UV flag evidences the second one.
   */
  /**
   * @param {object} [tuning]
   * @param {boolean} [tuning.payment]      request the SPC `payment` extension
   * @param {number[]} [tuning.algorithms]  COSE algorithms to offer, in order
   */
  beginRegistration({
    payment = true,
    algorithms = [COSE_ALG.ES256, COSE_ALG.EdDSA, COSE_ALG.RS256],
    attachment = null,
  } = {}) {
    const challenge = randomBytes(32);
    this.registrationChallenge = challenge;

    return {
      challenge,
      rp: { id: this.rpId, name: this.rpName },
      user: {
        id: b64uDecode(this.state.user.id),
        name: this.state.user.name,
        displayName: this.state.user.displayName,
      },
      pubKeyCredParams: algorithms.map((alg) => ({ type: 'public-key', alg })),
      excludeCredentials: this.credentials.map((c) => ({
        type: 'public-key',
        id: b64uDecode(c.credentialId),
        transports: c.transports?.length ? c.transports : undefined,
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
        // Steering only. "cross-platform" tells the browser to skip this
        // machine's built-in authenticator and go to the QR code or a security
        // key; omitting it lets the browser offer everything. A relying party
        // can express a preference and nothing more — the picker belongs to
        // the browser, and a site that could silently choose the authenticator
        // would be a phishing primitive.
        ...(attachment ? { authenticatorAttachment: attachment } : {}),
      },
      // WebAuthn Level 3 hints, ignored by browsers that predate them.
      ...(attachment
        ? { hints: attachment === 'cross-platform' ? ['hybrid', 'security-key'] : ['client-device'] }
        : {}),
      attestation: 'none',
      // A local biometric is a couple of seconds; scanning a QR code means
      // picking up the phone, unlocking it and opening the camera. WebAuthn
      // suggests around 300s where user verification is required, and rushing
      // a cross-device enrolment into 120s is how people end up retrying.
      timeout: attachment === 'cross-platform' ? 300000 : 120000,
      extensions: {
        credProps: true,
        // Marks the credential as usable by Secure Payment Confirmation.
        // Only requested where the browser exposes PaymentRequest at all: the
        // SPC specification has create() throw NotSupportedError when the user
        // agent does not support SPC, which would otherwise block enrolment
        // outright on browsers that have no SPC implementation.
        ...(payment ? { payment: { isPayment: true } } : {}),
      },
    };
  }

  async finishRegistration(credential, { paymentExtensionRequested = false } = {}) {
    const response = credential.response;
    const clientDataJson = textDecoder.decode(response.clientDataJSON);
    const clientData = JSON.parse(clientDataJson);
    const checks = [];
    const add = (label, status, detail) => checks.push({ label, status, detail });

    add(
      'clientData.type is "webauthn.create"',
      clientData.type === 'webauthn.create' ? PASS : FAIL,
      clientData.type,
    );
    add(
      'Registration challenge matches the one issued',
      this.registrationChallenge && bytesEqual(b64uDecode(clientData.challenge), this.registrationChallenge)
        ? PASS
        : FAIL,
      clientData.challenge,
    );
    add('Origin matches the expected relying party origin', clientData.origin === this.origin ? PASS : FAIL, clientData.origin);

    const attestationObject = cborDecode(new Uint8Array(response.attestationObject));
    const authData = parseAuthenticatorData(attestationObject.get('authData'));
    const expectedRpIdHash = await sha256(textEncoder.encode(this.rpId));

    add('rpIdHash matches SHA-256(rpId)', bytesEqual(authData.rpIdHash, expectedRpIdHash) ? PASS : FAIL, this.rpId);
    add('UP flag set (user present)', authData.flags.userPresent ? PASS : FAIL, 'flags & 0x01');
    add(
      'UV flag set (user verified — second SCA element)',
      authData.flags.userVerified ? PASS : FAIL,
      'flags & 0x04',
    );

    // Prefer the browser-provided SPKI; fall back to the COSE key in authData.
    let jwk;
    let alg;
    let keySource;
    const spki = typeof response.getPublicKey === 'function' ? response.getPublicKey() : null;
    if (spki) {
      alg = response.getPublicKeyAlgorithm();
      const { importAlgorithm } = importParamsFor(alg);
      const key = await crypto.subtle.importKey('spki', spki, importAlgorithm, true, ['verify']);
      jwk = await crypto.subtle.exportKey('jwk', key);
      keySource = 'AuthenticatorAttestationResponse.getPublicKey()';
    } else {
      const converted = coseKeyToJwk(authData.coseKey);
      jwk = converted.jwk;
      alg = converted.alg;
      keySource = 'COSE key decoded from attestationObject';
    }
    delete jwk.key_ops;
    delete jwk.alg;

    const credentialId = b64uEncode(credential.rawId);
    const extensions = credential.getClientExtensionResults?.() ?? {};

    const record = {
      credentialId,
      jwk,
      alg,
      algLabel: ALG_LABELS[String(alg)] ?? `COSE alg ${alg}`,
      signCount: authData.signCount,
      aaguid: authData.aaguidFormatted ?? formatAaguid(new Uint8Array(16)),
      transports: response.getTransports?.() ?? [],
      backupEligible: authData.flags.backupEligible,
      backupState: authData.flags.backupState,
      residentKey: extensions.credProps?.rk ?? null,
      // Chrome does not echo the payment extension in the client extension
      // results, so record what we asked for rather than claiming a capability
      // we cannot observe. SPC is attempted and falls back regardless.
      paymentExtensionRequested,
      keySource,
      createdAt: nowIso(),
    };

    const ok = checks.every((c) => c.status !== FAIL);
    if (ok) {
      this.state.credentials[credentialId] = record;
      this.#save();
    }

    return { ok, checks, record, clientData, authData, extensions };
  }

  removeCredential(credentialId) {
    delete this.state.credentials[credentialId];
    this.#save();
  }

  // ------------------------------------------------------- dynamic linking

  /**
   * Article 5(1)(a)-(c): the authentication code must be linked to the amount
   * and the payee, and any change to either must invalidate it.
   *
   * The challenge is SHA-256(nonce ‖ canonical-JSON(transaction)). The nonce
   * keeps the challenge unpredictable (Art. 4) and prevents an attacker who
   * knows the transaction from precomputing it; the canonical encoding keeps
   * the hash reproducible on verification.
   */
  async createAuthorisationChallenge(subject, { scaDecision, bind = true } = {}) {
    const nonce = randomBytes(32);
    const canonical = bind ? canonicalJson(subject) : null;
    // An unbound action — signing in — has no amount or payee to commit to, so
    // the challenge is simply unpredictable. Binding is what Art. 5 adds on top
    // for payments; it is not what makes a challenge safe in the first place.
    const challenge = bind
      ? await sha256(concatBytes(nonce, textEncoder.encode(canonical)))
      : randomBytes(32);
    const challengeB64u = b64uEncode(challenge);

    const context = {
      challenge: challengeB64u,
      nonce: b64uEncode(nonce),
      bound: bind,
      subject,
      transaction: subject,
      canonical,
      issuedAt: Date.now(),
      expiresAt: Date.now() + CHALLENGE_TTL_MS,
      consumed: false,
      scaDecision: scaDecision ?? null,
    };
    this.pending.set(challengeB64u, context);

    return {
      ...context,
      challengeBytes: challenge,
      allowCredentials: this.credentials.map((c) => ({
        type: 'public-key',
        id: b64uDecode(c.credentialId),
        transports: c.transports?.length ? c.transports : undefined,
      })),
      timeout: CHALLENGE_TTL_MS,
      rpId: this.rpId,
      userVerification: 'required',
    };
  }

  /**
   * Verify an assertion and decide whether to execute `executionPayload` — the
   * transaction the client is *asking* to have executed, which is not
   * necessarily the one that was signed. Proving those are the same object is
   * the whole point of dynamic linking.
   */
  async verifyAuthorisation({ assertion, executionPayload }) {
    const checks = [];
    const add = (id, label, status, detail, article) => {
      checks.push({ id, label, status, detail, article });
      return status;
    };

    const clientDataBytes = bytes(assertion.response.clientDataJSON);
    const clientDataJson = textDecoder.decode(clientDataBytes);
    let clientData;
    try {
      clientData = JSON.parse(clientDataJson);
    } catch {
      add('clientdata', 'clientDataJSON parses as JSON', FAIL, 'Malformed client data');
      return { ok: false, checks, clientDataJson };
    }

    const credentialId = b64uEncode(assertion.rawId);
    const record = this.state.credentials[credentialId];

    add(
      'known-credential',
      'Credential is enrolled to this payer',
      record ? PASS : FAIL,
      record ? `${credentialId.slice(0, 16)}… (${record.algLabel})` : `Unknown credential ${credentialId.slice(0, 16)}…`,
      'RTS Art. 4',
    );

    const isSpc = clientData.type === 'payment.get';
    add(
      'type',
      'clientData.type is an assertion type (webauthn.get, or payment.get for SPC)',
      clientData.type === 'webauthn.get' || isSpc ? PASS : FAIL,
      clientData.type,
    );
    add(
      'origin',
      'clientData.origin matches the relying party origin',
      clientData.origin === this.origin ? PASS : FAIL,
      `${clientData.origin} (expected ${this.origin})`,
      'RTS Art. 5(2)(b)',
    );
    add(
      'cross-origin',
      'Assertion was not produced in a cross-origin frame',
      clientData.crossOrigin ? FAIL : PASS,
      `crossOrigin=${Boolean(clientData.crossOrigin)}`,
    );

    // --- the dynamic-linking core ------------------------------------------
    const context = this.pending.get(clientData.challenge);
    add(
      'challenge-known',
      'Challenge was issued by this server and is still open',
      context ? (context.consumed ? FAIL : PASS) : FAIL,
      context
        ? context.consumed
          ? 'Challenge has already been consumed — replay rejected.'
          : `Issued ${new Date(context.issuedAt).toISOString()}`
        : 'No pending authorisation matches this challenge.',
      'RTS Art. 4(3) / Art. 5(1)(c)',
    );

    const expired = context ? Date.now() > context.expiresAt : false;
    add(
      'challenge-fresh',
      'Challenge is within its validity window',
      context ? (expired ? FAIL : PASS) : SKIP,
      context ? `TTL ${Math.round(CHALLENGE_TTL_MS / 1000)}s` : 'No challenge context',
      'RTS Art. 4(3)(b)',
    );

    let recomputed = null;
    let linkingStatus = SKIP;
    if (context && !context.bound) {
      add(
        'dynamic-linking',
        'Dynamic linking not applicable to this action',
        SKIP,
        'A sign-in has no amount and no payee to bind. RTS Art. 5 governs remote electronic payment transactions; the protection here comes from the challenge being unpredictable, single-use and origin-bound.',
        'RTS Art. 5(1)',
      );
    } else if (context) {
      const canonicalExecuted = canonicalJson(executionPayload);
      recomputed = b64uEncode(
        await sha256(concatBytes(b64uDecode(context.nonce), textEncoder.encode(canonicalExecuted))),
      );
      linkingStatus = recomputed === clientData.challenge && !context.consumed ? PASS : FAIL;
      add(
        'dynamic-linking',
        'Action to be carried out re-hashes to the signed challenge',
        linkingStatus,
        linkingStatus === PASS
          ? 'Amount and payee are unchanged since the payer authorised them.'
          : `Recomputed ${recomputed.slice(0, 24)}… ≠ signed ${clientData.challenge.slice(0, 24)}…`,
        'RTS Art. 5(1)(a)-(c)',
      );
      if (linkingStatus === FAIL) {
        const diff = diffTransactions(context.transaction, executionPayload);
        if (diff.length) {
          add(
            'linking-diff',
            'Fields altered after authorisation',
            FAIL,
            diff.map((d) => `${d.path}: ${JSON.stringify(d.signed)} → ${JSON.stringify(d.submitted)}`).join('; '),
            'RTS Art. 5(1)(c)',
          );
        }
      }
    } else {
      add('dynamic-linking', 'Action to be carried out re-hashes to the signed challenge', SKIP, 'No challenge context to re-hash against.', 'RTS Art. 5(1)(a)-(c)');
    }

    // --- Secure Payment Confirmation: browser-enforced visual dynamic linking
    if (isSpc) {
      const payment = clientData.payment ?? {};
      const authoritative = context?.transaction ?? executionPayload;
      // The browser may normalise "150.00" to "150", so compare the value
      // numerically; the currency still has to match exactly.
      const displayedAmount = Number(payment.total?.value);
      const authorisedAmount = Number(authoritative.amount);
      add(
        'spc-amount',
        'SPC-displayed amount is signed and matches the authorised amount',
        Number.isFinite(displayedAmount) &&
        displayedAmount === authorisedAmount &&
        payment.total?.currency === authoritative.currency
          ? PASS
          : FAIL,
        `displayed ${payment.total?.value} ${payment.total?.currency}; authorised ${authoritative.amount} ${authoritative.currency}`,
        'RTS Art. 5(1)(b)',
      );
      add(
        'spc-payee',
        'SPC-displayed payee is signed and matches the authorised payee',
        payment.payeeName === authoritative.payee?.name ? PASS : FAIL,
        `displayed "${payment.payeeName}"; authorised "${authoritative.payee?.name}"`,
        'RTS Art. 5(1)(b)',
      );
      add(
        'spc-rp',
        'SPC assertion was produced for this relying party',
        payment.rpId === this.rpId ? PASS : FAIL,
        `${payment.rpId} (expected ${this.rpId})`,
      );
    }

    // --- authenticator data ------------------------------------------------
    const authDataBytes = bytes(assertion.response.authenticatorData);
    const authData = parseAuthenticatorData(authDataBytes);
    const expectedRpIdHash = await sha256(textEncoder.encode(this.rpId));

    add('rpidhash', 'rpIdHash matches SHA-256(rpId)', bytesEqual(authData.rpIdHash, expectedRpIdHash) ? PASS : FAIL, this.rpId);
    add('up', 'UP flag set — the payer acted on the authenticator', authData.flags.userPresent ? PASS : FAIL, 'flags & 0x01');
    add(
      'uv',
      'UV flag set — second authentication element evidenced',
      authData.flags.userVerified ? PASS : FAIL,
      authData.flags.userVerified
        ? 'Biometric or device PIN verified locally (inherence/knowledge) alongside possession of the authenticator.'
        : 'Only possession was evidenced; this is single-factor and cannot satisfy SCA.',
      'PSD2 Art. 4(30) / RTS Art. 6-8',
    );

    if (record) {
      const counterOk = authData.signCount === 0 && record.signCount === 0
        ? true
        : authData.signCount > record.signCount || (authData.signCount === 0 && record.signCount === 0);
      add(
        'signcount',
        'Signature counter is monotonic (clone detection)',
        authData.signCount === 0 && record.signCount === 0 ? WARN : counterOk ? PASS : FAIL,
        authData.signCount === 0 && record.signCount === 0
          ? 'Authenticator does not maintain a signature counter (normal for synced passkeys).'
          : `stored ${record.signCount} → presented ${authData.signCount}`,
        'RTS Art. 9 / Art. 2',
      );
    } else {
      add('signcount', 'Signature counter is monotonic (clone detection)', SKIP, 'No stored credential');
    }

    add(
      'backup',
      'Credential backup state recorded for risk monitoring',
      record ? (authData.flags.backupState ? WARN : PASS) : SKIP,
      record
        ? authData.flags.backupState
          ? 'Passkey is synced across the payer’s devices (BE=1, BS=1). Permitted, but the possession element is a key that exists on multiple devices — factor it into Art. 2 monitoring.'
          : 'Credential is device-bound (BS=0).'
        : 'No stored credential',
      'RTS Art. 2 / Art. 9',
    );

    // --- signature ---------------------------------------------------------
    let signatureStatus = SKIP;
    if (record) {
      try {
        const { importAlgorithm, verifyAlgorithm } = importParamsFor(record.alg);
        const key = await crypto.subtle.importKey('jwk', record.jwk, importAlgorithm, false, ['verify']);
        const signed = concatBytes(authDataBytes, await sha256(clientDataBytes));
        let signature = bytes(assertion.response.signature);
        if (record.alg === COSE_ALG.ES256) signature = derToRawEcdsaSignature(signature, 32);
        const valid = await crypto.subtle.verify(verifyAlgorithm, key, signature, signed);
        signatureStatus = valid ? PASS : FAIL;
        add(
          'signature',
          'Signature verifies over authenticatorData ‖ SHA-256(clientDataJSON)',
          signatureStatus,
          `${record.algLabel}; ${valid ? 'valid' : 'INVALID'}`,
          'RTS Art. 4(2)',
        );
      } catch (error) {
        signatureStatus = FAIL;
        add('signature', 'Signature verifies over authenticatorData ‖ SHA-256(clientDataJSON)', FAIL, String(error));
      }
    } else {
      add('signature', 'Signature verifies over authenticatorData ‖ SHA-256(clientDataJSON)', SKIP, 'No public key on file');
    }

    const ok = checks.every((c) => c.status !== FAIL);

    // A challenge is single-use whatever the outcome: an authentication code
    // may not be reusable (Art. 4(3)(a)).
    if (context) {
      context.consumed = true;
      context.consumedAt = Date.now();
    }

    const receipt = ok
      ? this.#apply(executionPayload, { context, authData, clientData, credentialId })
      : null;

    if (ok && record) {
      record.signCount = Math.max(record.signCount, authData.signCount);
      record.backupState = authData.flags.backupState;
      this.#save();
    }

    return {
      ok,
      checks,
      clientData,
      clientDataJson,
      authData,
      recomputedChallenge: recomputed,
      signedChallenge: clientData.challenge,
      context,
      receipt,
      credentialRecord: record ?? null,
      signature: b64uEncode(assertion.response.signature),
      userHandle: assertion.response.userHandle ? b64uEncode(assertion.response.userHandle) : null,
    };
  }

  /** Carry out an authenticated action, once every verification check passed. */
  #apply(subject, meta) {
    const entry = this.#record(subject, {
      authenticated: true,
      method: meta.clientData?.type ?? 'webauthn.get',
      credentialId: meta.credentialId,
      signCount: meta.authData.signCount,
      exemption: null,
    });

    const now = Date.now();
    if (subject.type === 'login') {
      this.state.session = { signedInAt: now, lastScaAt: now, accessCount: this.state.session.accessCount + 1 };
    } else if (subject.type === 'beneficiary') {
      this.state.beneficiaries[subject.beneficiaryId] = { ...subject, addedAt: nowIso(), authenticated: true };
    } else {
      // Art. 16: the running counters reset once SCA has been applied.
      this.state.lowValueCounters = { amountEur: 0, count: 0 };
    }

    this.#save();
    return entry;
  }

  /** Carry out an action that an exemption let through without SCA. */
  applyExempt(subject, decision, amountEur) {
    const entry = this.#record(subject, {
      authenticated: false,
      exemption: decision.chosenExemption,
      credentialId: null,
    });

    if (subject.type === 'login') {
      // Art. 10 resumption does not refresh lastScaAt: the window runs from the
      // last SCA, not from the last exempted access.
      this.state.session = {
        ...this.state.session,
        signedInAt: Date.now(),
        accessCount: this.state.session.accessCount + 1,
      };
    } else if (decision.chosenExemption?.article === 'RTS Art. 16') {
      this.state.lowValueCounters = {
        amountEur: this.state.lowValueCounters.amountEur + amountEur,
        count: this.state.lowValueCounters.count + 1,
      };
    }

    this.#save();
    return entry;
  }

  #record(subject, meta) {
    this.state.seq += 1;
    const entry = {
      sequence: this.state.seq,
      executedAt: nowIso(),
      kind: subject.type,
      subject,
      transaction: subject,
      ...meta,
    };
    this.state.ledger.unshift(entry);
    return entry;
  }

  get session() {
    return this.state.session;
  }

  get beneficiaries() {
    return Object.values(this.state.beneficiaries);
  }

  /** Simulated ageing of the last SCA, so the Art. 10 window is demonstrable. */
  ageLastSca(days) {
    if (!this.state.session.lastScaAt) return;
    this.state.session.lastScaAt -= days * 86_400_000;
    this.#save();
  }

  get ledger() {
    return this.state.ledger;
  }
}

/** Flat path-wise diff between the signed transaction and the submitted one. */
export function diffTransactions(signed, submitted, prefix = '') {
  const out = [];
  const keys = new Set([...Object.keys(signed ?? {}), ...Object.keys(submitted ?? {})]);
  for (const key of keys) {
    const a = signed?.[key];
    const b = submitted?.[key];
    const path = prefix ? `${prefix}.${key}` : key;
    if (a && b && typeof a === 'object' && typeof b === 'object') {
      out.push(...diffTransactions(a, b, path));
    } else if (canonicalJson(a ?? null) !== canonicalJson(b ?? null)) {
      out.push({ path, signed: a, submitted: b });
    }
  }
  return out;
}

export const STATUS = { PASS, FAIL, SKIP, WARN };
