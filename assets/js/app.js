/**
 * UI orchestration: wires the form, the exemption engine, the WebAuthn client
 * and the simulated PSP together, and renders the evidence at every step.
 */

import {
  b64uDecode,
  b64uEncode,
  canonicalJson,
  formatMoney,
  normaliseAmount,
  nowIso,
  prettyJson,
  toHex,
} from './util.js';
import { BankServer, STATUS, diffTransactions } from './bank-server.js';
import { assess, summarise, toEurEquivalent, THRESHOLDS } from './sca-engine.js';
import {
  authorisePlain,
  authoriseWithSpc,
  createPasskey,
  friendlyWebauthnError,
  probeEnvironment,
} from './client.js';
import { describeFlags } from './webauthn-codec.js';

const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const auditLog = [];
let env = null;
let server = null;

/** Everything about the payment currently in flight. */
const flow = {
  transaction: null,
  decision: null,
  challenge: null,
  displayedAt: null,
  lastAssertion: null,
  lastPayload: null,
  lastMethod: null,
};

// ------------------------------------------------------------------ logging

function log(level, message, data) {
  const entry = { at: new Date().toISOString(), level, message, data };
  auditLog.push(entry);
  const list = $('audit-log');
  const li = document.createElement('li');
  li.className = level;
  li.innerHTML = `<span class="t">${entry.at.slice(11, 19)}</span><span class="m">${esc(message)}${
    data ? `<br><span style="color:var(--ink-3)">${esc(typeof data === 'string' ? data : canonicalJson(data))}</span>` : ''
  }</span>`;
  list.append(li);
  list.parentElement.scrollTop = list.parentElement.scrollHeight;
  list.scrollTop = list.scrollHeight;
}

// -------------------------------------------------------------- environment

function renderEnvBadges() {
  const items = [
    { ok: env.secureContext, label: `secure context: ${env.secureContext ? 'yes' : 'no'}` },
    { ok: true, label: `rpId: ${env.rpId}`, neutral: true },
    { ok: env.webauthn, label: `WebAuthn: ${env.webauthn ? 'available' : 'missing'}` },
    { ok: env.platformAuthenticator, label: `platform authenticator: ${env.platformAuthenticator ? 'yes' : 'no'}`, warnIfNo: true },
    { ok: env.spc, label: `Secure Payment Confirmation: ${env.spc ? 'yes' : 'no'}`, warnIfNo: true },
  ];
  $('env-badges').innerHTML = items
    .map((item) => {
      const cls = item.neutral ? '' : item.ok ? 'ok' : item.warnIfNo ? 'warn' : 'no';
      return `<li class="${cls}">${esc(item.label)}</li>`;
    })
    .join('');
}

// ----------------------------------------------------------------- step 1

function renderCredentials() {
  const list = $('cred-list');
  const creds = server.credentials;
  if (!creds.length) {
    list.innerHTML = '<p class="placeholder">No passkey enrolled yet. Enrolment is what binds a public key to this relying party.</p>';
    $('btn-register').textContent = 'Create passkey';
    return;
  }
  $('btn-register').textContent = 'Enrol another passkey';
  list.innerHTML = creds
    .map((c) => {
      const chips = [
        `<span class="chip">${esc(c.algLabel)}</span>`,
        c.transports?.length ? `<span class="chip">${esc(c.transports.join(', '))}</span>` : '',
        c.residentKey ? '<span class="chip good">discoverable</span>' : '',
        c.paymentCapable ? '<span class="chip good">SPC-enabled</span>' : '',
        c.backupEligible
          ? `<span class="chip warn">BE=1 BS=${c.backupState ? 1 : 0} (synced)</span>`
          : '<span class="chip">device-bound</span>',
      ].join('');
      return `<div class="cred">
        <div class="cred-main">
          <h3>Passkey · ${esc(c.credentialId.slice(0, 10))}…</h3>
          <div class="chips">${chips}</div>
          <dl class="kv">
            <dt>AAGUID</dt><dd>${esc(c.aaguid)}</dd>
            <dt>Sign count</dt><dd>${c.signCount}</dd>
            <dt>Enrolled</dt><dd>${esc(c.createdAt)}</dd>
          </dl>
        </div>
        <button type="button" class="btn tiny danger" data-remove="${esc(c.credentialId)}">Forget</button>
      </div>`;
    })
    .join('');

  list.querySelectorAll('[data-remove]').forEach((btn) => {
    btn.addEventListener('click', () => {
      server.removeCredential(btn.dataset.remove);
      log('warn', 'Credential removed from the PSP registry');
      renderCredentials();
      refreshGates();
    });
  });
}

async function onRegister() {
  const button = $('btn-register');
  button.disabled = true;
  $('register-hint').textContent = 'Follow your device prompt…';
  try {
    const options = server.beginRegistration();
    log('step', 'POST /webauthn/register/begin → options issued', {
      rpId: options.rp.id,
      userVerification: options.authenticatorSelection.userVerification,
      algs: options.pubKeyCredParams.map((p) => p.alg),
    });
    const credential = await createPasskey(options);
    const result = await server.finishRegistration(credential);
    $('reg-result').innerHTML = renderChecklist(result.checks.map((c) => ({ ...c, status: c.status })));
    if (result.ok) {
      log('good', `Passkey enrolled (${result.record.algLabel}) via ${result.record.keySource}`);
      if (result.record.backupEligible) {
        log('warn', 'Credential is backup-eligible: the possession element is a synced key. Record it for Art. 2 monitoring.');
      }
    } else {
      log('bad', 'Registration rejected by the server checks');
    }
    renderCredentials();
    refreshGates();
  } catch (error) {
    log('bad', `Registration failed — ${friendlyWebauthnError(error)}`);
    $('reg-result').innerHTML = `<div class="verdict fail"><span class="icon">✗</span><div><h3>Registration failed</h3><p>${esc(
      friendlyWebauthnError(error),
    )}</p></div></div>`;
  } finally {
    button.disabled = false;
    $('register-hint').textContent = '';
  }
}

// ----------------------------------------------------------------- step 2

function readTransaction() {
  const amount = normaliseAmount($('f-amount').value);
  return {
    schema: 'sca-rts-demo/transaction/1',
    txnId: `TX-${b64uEncode(crypto.getRandomValues(new Uint8Array(6)))}`,
    amount,
    currency: $('f-currency').value,
    payee: { name: $('f-payee').value.trim(), iban: $('f-iban').value.trim().toUpperCase() },
    debtorAccount: 'IE64IRCE92050112345678',
    reference: $('f-reference').value.trim(),
    initiatedAt: nowIso(),
    channel: 'web-remote',
  };
}

function readContext() {
  return {
    trustedBeneficiary: $('c-trusted').checked,
    recurringMandate: $('c-recurring').checked,
    firstOfSeries: $('c-first').checked,
    sameOwnerSamePsp: $('c-self').checked,
    corporateProcess: $('c-corporate').checked,
    forceSca: $('c-force').checked,
    riskScore: Number($('f-risk').value),
    riskThreshold: 40,
    fraudRate: Number($('f-fraud').value),
    lowValueCounters: server.lowValueCounters,
  };
}

function onAssess(event) {
  event?.preventDefault();
  const transaction = readTransaction();
  const context = readContext();
  const decision = assess(transaction, context);

  flow.transaction = transaction;
  flow.decision = decision;
  flow.challenge = null;
  flow.lastAssertion = null;

  log('step', `POST /payments → ${formatMoney(transaction.amount, transaction.currency)} to ${transaction.payee.name}`);
  log(decision.scaRequired ? 'info' : 'warn', summarise(decision));

  renderScaDecision(decision, transaction);
  resetSection('step-link', 'link-body', 'Waiting for an SCA decision.');
  resetSection('step-auth', 'auth-body', 'Waiting for a dynamically linked challenge.');
  resetSection('step-verify', 'verify-body', 'No authorisation attempted yet.');
  $('step-sca').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function resetSection(sectionId, bodyId, placeholder) {
  $(sectionId).classList.add('is-idle');
  $(bodyId).innerHTML = `<p class="placeholder">${esc(placeholder)}</p>`;
}

// ----------------------------------------------------------------- step 3

function renderScaDecision(decision, transaction) {
  const section = $('step-sca');
  section.classList.remove('is-idle');

  const verdictClass = decision.scaRequired ? 'sca' : 'exempt';
  const icon = decision.scaRequired ? '🔐' : '⚡';
  const fx = decision.indicativeFx
    ? `<p class="hint">Assessed as €${decision.amountEur.toFixed(2)} equivalent${
        decision.unknownRate ? ' (no rate on file — treated 1:1)' : ' at an indicative demo rate'
      }; RTS thresholds are expressed in euro.</p>`
    : '';

  const rows = decision.candidates
    .map(
      (c) => `<li>
        <span class="art">${esc(c.article)}</span>
        <span class="name">${esc(c.name)}<span class="why">${esc(c.reason)}</span></span>
        <span class="state ${c.applies ? 'yes' : 'no'}">${c.applies ? 'available' : 'no'}</span>
      </li>`,
    )
    .join('');

  const actions = decision.scaRequired
    ? `<button type="button" class="btn primary" id="btn-proceed-sca">Generate dynamically linked challenge</button>`
    : `<div class="row">
         <button type="button" class="btn" id="btn-execute-exempt">Execute without SCA (use the exemption)</button>
         <button type="button" class="btn primary" id="btn-proceed-sca">Authenticate anyway</button>
       </div>
       <p class="hint">A PSP may always choose to authenticate. The payee’s PSP can also refuse an exemption and send the transaction back for SCA.</p>`;

  $('sca-body').innerHTML = `
    <div class="verdict ${verdictClass}">
      <span class="icon">${icon}</span>
      <div>
        <h3>${decision.scaRequired ? 'Strong customer authentication required' : 'Exemption available'}</h3>
        <p>${esc(summarise(decision))}</p>
      </div>
    </div>
    ${fx}
    <ul class="exemptions">${rows}</ul>
    ${actions}`;

  $('btn-proceed-sca')?.addEventListener('click', () => beginAuthorisation(transaction, decision));
  $('btn-execute-exempt')?.addEventListener('click', () => executeExempt(transaction, decision));
}

function executeExempt(transaction, decision) {
  const entry = server.executeExempt(transaction, decision, decision.amountEur);
  log('warn', `Executed without SCA under ${decision.chosenExemption.article} — ${decision.chosenExemption.name}`, {
    txnId: transaction.txnId,
  });
  renderCounters();
  renderLedger();
  $('sca-body').insertAdjacentHTML(
    'beforeend',
    `<div class="verdict exempt"><span class="icon">✓</span><div><h3>Payment #${entry.sequence} executed under an exemption</h3><p>No authentication code was generated, so Article 5 dynamic linking did not apply to this payment. The Article 16 counters on the right have moved.</p></div></div>`,
  );
}

// ----------------------------------------------------------------- step 4

async function beginAuthorisation(transaction, decision) {
  const challenge = await server.createAuthorisationChallenge(transaction, { scaDecision: decision });
  flow.challenge = challenge;
  flow.displayedAt = nowIso();

  log('step', 'POST /payments/{id}/sca/begin → challenge = SHA-256(nonce ‖ canonical-JSON(transaction))', {
    challenge: challenge.challenge,
  });

  renderLinking(transaction, challenge);
  renderAuthorise(transaction, challenge);
  $('step-link').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderLinking(transaction, challenge) {
  $('step-link').classList.remove('is-idle');
  $('link-body').innerHTML = `
    <div class="confirm" id="confirm-panel">
      <span class="eyebrow">Confirm this payment</span>
      <div>
        <div class="amount">${esc(formatMoney(transaction.amount, transaction.currency))}</div>
        <p class="to">to</p>
        <div class="payee">${esc(transaction.payee.name)}</div>
      </div>
      <div class="meta">
        <span>${esc(transaction.payee.iban)}</span>
        ${transaction.reference ? `<span>ref ${esc(transaction.reference)}</span>` : ''}
        <span>${esc(transaction.txnId)}</span>
      </div>
      <p class="foot">Article 5(1)(a): the payer must be made aware of the amount and the payee before authenticating. Displayed at ${esc(
        flow.displayedAt,
      )} and recorded in the audit trail.</p>
    </div>

    <div class="stack">
      <div class="label-row"><h3>Canonical transaction</h3><span class="tag">${challenge.canonical.length} bytes hashed</span></div>
      <pre class="codeblock wrap-any">${esc(challenge.canonical)}</pre>
    </div>

    <div class="stack">
      <div class="label-row"><h3>Challenge derivation</h3><span class="tag">server-side only</span></div>
      <dl class="kv">
        <dt>nonce (32 B)</dt><dd>${esc(toHex(b64uDecode(challenge.nonce), { groupsOf: 4 }))}</dd>
        <dt>challenge</dt><dd>${esc(challenge.challenge)}</dd>
        <dt>SHA-256 hex</dt><dd>${esc(toHex(b64uDecode(challenge.challenge), { groupsOf: 4 }))}</dd>
        <dt>expires</dt><dd>${esc(new Date(challenge.expiresAt).toISOString())}</dd>
      </dl>
      <p class="hint">The nonce and the authoritative transaction stay on the server. The browser only ever sees the 32-byte challenge — which is exactly why the server has to re-hash at verification time rather than trust what comes back.</p>
    </div>`;
}

// ----------------------------------------------------------------- step 5

function renderAuthorise(transaction, challenge) {
  $('step-auth').classList.remove('is-idle');
  const spcNote = env.spc
    ? 'Secure Payment Confirmation is available here: the browser will render the amount and payee itself and sign them into clientDataJSON.'
    : 'Secure Payment Confirmation is not available in this browser, so the page-rendered panel above is the Article 5(1)(a) confirmation. The challenge binding is identical either way.';

  $('auth-body').innerHTML = `
    <p class="hint">${esc(spcNote)}</p>
    <div class="attack">
      <h3>Attacker simulation</h3>
      <p>Tamper with the transaction <em>after</em> the payer authorised it — the manipulated payload is what gets submitted for execution, while the signature still covers the original challenge.</p>
      <select id="tamper-mode" aria-label="Tampering to apply after authorisation">
        <option value="none">No tampering — honest submission</option>
        <option value="amount">Change the amount (×100)</option>
        <option value="payee">Redirect to a different payee and IBAN</option>
        <option value="both">Change both amount and payee</option>
        <option value="reference">Change only the reference (not amount or payee)</option>
      </select>
    </div>
    <div class="row">
      ${env.spc ? '<button type="button" class="btn primary" id="btn-auth-spc">Authorise with Secure Payment Confirmation</button>' : ''}
      <button type="button" class="btn ${env.spc ? '' : 'primary'}" id="btn-auth-plain">Authorise with passkey</button>
      <button type="button" class="btn ghost" id="btn-replay" disabled>Replay the last authorisation</button>
    </div>`;

  $('btn-auth-spc')?.addEventListener('click', () => authorise('spc', transaction, challenge));
  $('btn-auth-plain').addEventListener('click', () => authorise('plain', transaction, challenge));
  $('btn-replay').addEventListener('click', () => replay());
  refreshGates();
}

function applyTampering(transaction, mode) {
  const clone = structuredClone(transaction);
  if (mode === 'amount' || mode === 'both') {
    clone.amount = normaliseAmount(Number(transaction.amount) * 100);
  }
  if (mode === 'payee' || mode === 'both') {
    clone.payee = { name: 'Quick Cash Holdings Ltd', iban: 'LT601010012345678901' };
  }
  if (mode === 'reference') {
    clone.reference = 'ORDER-0001';
  }
  return clone;
}

async function authorise(method, transaction, challenge) {
  const buttons = ['btn-auth-spc', 'btn-auth-plain'].map($).filter(Boolean);
  buttons.forEach((b) => (b.disabled = true));

  try {
    log('step', `navigator.credentials.get() via ${method === 'spc' ? 'Secure Payment Confirmation' : 'plain WebAuthn'} — userVerification: required`);

    let assertion;
    let usedMethod = method;
    try {
      if (method === 'spc') {
        const result = await authoriseWithSpc({
          challengeBytes: challenge.challengeBytes,
          credentialIds: server.credentials.map((c) => b64uDecode(c.credentialId)),
          rpId: challenge.rpId,
          payeeName: transaction.payee.name,
          amount: transaction.amount,
          currency: transaction.currency,
          instrumentLabel: 'Demo Bank current account ••4321',
        });
        assertion = result.assertion;
      } else {
        const result = await authorisePlain({
          challengeBytes: challenge.challengeBytes,
          allowCredentials: challenge.allowCredentials,
          rpId: challenge.rpId,
          timeout: challenge.timeout,
        });
        assertion = result.assertion;
      }
    } catch (error) {
      if (method === 'spc') {
        log('warn', `SPC path unavailable (${friendlyWebauthnError(error)}) — falling back to plain WebAuthn`);
        const result = await authorisePlain({
          challengeBytes: challenge.challengeBytes,
          allowCredentials: challenge.allowCredentials,
          rpId: challenge.rpId,
          timeout: challenge.timeout,
        });
        assertion = result.assertion;
        usedMethod = 'plain';
      } else {
        throw error;
      }
    }

    const mode = $('tamper-mode')?.value ?? 'none';
    const executionPayload = applyTampering(transaction, mode);
    if (mode !== 'none') {
      log('bad', `Attacker rewrote the payload after authorisation (${mode})`, diffTransactions(transaction, executionPayload));
    }

    flow.lastAssertion = assertion;
    flow.lastPayload = executionPayload;
    flow.lastMethod = usedMethod;
    $('btn-replay').disabled = false;

    await verify(assertion, executionPayload, usedMethod);
  } catch (error) {
    log('bad', `Authorisation failed — ${friendlyWebauthnError(error)}`);
    $('step-verify').classList.remove('is-idle');
    $('verify-body').innerHTML = `<div class="verdict fail"><span class="icon">✗</span><div><h3>No assertion produced</h3><p>${esc(
      friendlyWebauthnError(error),
    )}</p></div></div>`;
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}

async function replay() {
  if (!flow.lastAssertion) return;
  log('step', 'Replaying the previous assertion against the server — the challenge has already been consumed');
  await verify(flow.lastAssertion, flow.lastPayload, flow.lastMethod, { replay: true });
}

// ----------------------------------------------------------------- step 6

async function verify(assertion, executionPayload, method, { replay = false } = {}) {
  const result = await server.verifyAuthorisation({ assertion, executionPayload });
  renderVerification(result, executionPayload, method, replay);

  if (result.ok) {
    log('good', `Authorisation accepted — payment #${result.receipt.sequence} executed`, { txnId: executionPayload.txnId });
  } else {
    const failed = result.checks.filter((c) => c.status === STATUS.FAIL).map((c) => c.label);
    log('bad', `Authorisation rejected — ${failed.length} check(s) failed`, failed);
  }
  renderCounters();
  renderLedger();
  $('step-verify').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderChecklist(checks) {
  const mark = { pass: '✓', fail: '✗', warn: '!', skip: '–' };
  return `<ul class="checklist">${checks
    .map(
      (c) => `<li class="${c.status}">
        <span class="mark">${mark[c.status] ?? '·'}</span>
        <div>
          <div class="label">${esc(c.label)}</div>
          ${c.detail ? `<div class="detail">${esc(c.detail)}</div>` : ''}
          ${c.article ? `<div class="art">${esc(c.article)}</div>` : ''}
        </div>
      </li>`,
    )
    .join('')}</ul>`;
}

function renderVerification(result, executionPayload, method, replayed) {
  $('step-verify').classList.remove('is-idle');

  const failedLinking = result.checks.find((c) => c.id === 'dynamic-linking' && c.status === STATUS.FAIL);
  const verdict = result.ok
    ? `<div class="verdict ok"><span class="icon">✓</span><div><h3>Payment executed</h3><p>Every check passed. The transaction credited to ${esc(
        executionPayload.payee.name,
      )} for ${esc(formatMoney(executionPayload.amount, executionPayload.currency))} is byte-for-byte the one the payer saw and signed.</p></div></div>`
    : `<div class="verdict fail"><span class="icon">✗</span><div><h3>Authorisation rejected — nothing executed</h3><p>${
        replayed
          ? 'The assertion is cryptographically valid, but its challenge was already consumed. An authentication code may not be reusable (Art. 4(3)(a)).'
          : failedLinking
            ? 'The signature verifies, but the transaction submitted for execution does not re-hash to the challenge the payer signed. This is Article 5(1)(d) doing its job.'
            : 'One or more verification steps failed.'
      }</p></div></div>`;

  const flags = describeFlags(result.authData.flags)
    .map((f) => `<span class="chip ${f.value ? (f.key === 'BS' ? 'warn' : 'good') : ''}">${f.key}=${f.value ? 1 : 0}</span>`)
    .join('');

  const hashes = result.recomputedChallenge
    ? `<div class="hash-compare">
         <div class="pair ${result.recomputedChallenge === result.signedChallenge ? 'match' : 'mismatch'}">
           <span>signed challenge</span><code>${esc(result.signedChallenge)}</code>
         </div>
         <div class="pair ${result.recomputedChallenge === result.signedChallenge ? 'match' : 'mismatch'}">
           <span>re-hash of submitted</span><code>${esc(result.recomputedChallenge)}</code>
         </div>
       </div>`
    : '';

  $('verify-body').innerHTML = `
    ${verdict}
    ${hashes}
    ${renderChecklist(result.checks)}
    <div class="stack">
      <div class="label-row"><h3>clientDataJSON (signed)</h3><span class="tag">${esc(method === 'spc' ? 'payment.get' : 'webauthn.get')}</span></div>
      <pre class="codeblock wrap-any">${esc(prettyJson(result.clientData))}</pre>
    </div>
    <div class="stack">
      <div class="label-row"><h3>authenticatorData</h3><span class="tag">${result.authData.raw.length} bytes</span></div>
      <div class="chips">${flags}</div>
      <dl class="kv">
        <dt>rpIdHash</dt><dd>${esc(toHex(result.authData.rpIdHash, { groupsOf: 4 }))}</dd>
        <dt>signCount</dt><dd>${result.authData.signCount}</dd>
        <dt>signature</dt><dd>${esc(result.signature)}</dd>
      </dl>
    </div>
    <div class="stack">
      <div class="label-row"><h3>Transaction submitted for execution</h3><span class="tag">what the server was asked to do</span></div>
      <pre class="codeblock wrap-any">${esc(canonicalJson(executionPayload))}</pre>
    </div>
    <div class="row">
      <button type="button" class="btn" id="btn-new-challenge">Issue a fresh challenge and retry</button>
    </div>`;

  $('btn-new-challenge').addEventListener('click', () => {
    if (flow.transaction && flow.decision) beginAuthorisation(flow.transaction, flow.decision);
  });
}

// ------------------------------------------------------------------- rail

function renderCounters() {
  const c = server.lowValueCounters;
  const amountPct = Math.min(100, (c.amountEur / THRESHOLDS.lowValueCumulative) * 100);
  const countPct = Math.min(100, (c.count / THRESHOLDS.lowValueCount) * 100);
  $('counters').innerHTML = `
    <div class="counter-bar">
      <span>Cumulative since last SCA — €${c.amountEur.toFixed(2)} of €${THRESHOLDS.lowValueCumulative}</span>
      <span class="meter"><i class="${amountPct > 80 ? 'hot' : ''}" style="width:${amountPct}%"></i></span>
    </div>
    <div class="counter-bar">
      <span>Consecutive exempt payments — ${c.count} of ${THRESHOLDS.lowValueCount}</span>
      <span class="meter"><i class="${countPct > 80 ? 'hot' : ''}" style="width:${countPct}%"></i></span>
    </div>
    <p class="hint">Article 16 lets a payment through without SCA only while one of these counters still has room. Applying SCA resets both.</p>`;
}

function renderLedger() {
  const entries = server.ledger.slice(0, 8);
  if (!entries.length) {
    $('ledger').innerHTML = '<p class="placeholder">Nothing executed yet.</p>';
    return;
  }
  $('ledger').innerHTML = entries
    .map(
      (e) => `<div class="ledger-item">
        <div class="top">
          <span class="amt">${esc(formatMoney(e.transaction.amount, e.transaction.currency))}</span>
          <span class="chip ${e.authenticated ? 'good' : 'warn'}">${e.authenticated ? 'SCA' : esc(e.exemption?.article ?? 'exempt')}</span>
        </div>
        <span>${esc(e.transaction.payee.name)}</span>
        <span class="meta">#${e.sequence} · ${esc(e.executedAt)}</span>
      </div>`,
    )
    .join('');
}

// ----------------------------------------------------------------- export

function exportAudit() {
  const record = {
    generatedAt: nowIso(),
    disclaimer: 'Demonstration artefact produced entirely in the browser. Not evidence of anything.',
    environment: env,
    relyingParty: { rpId: server.rpId, origin: server.origin },
    credentials: server.credentials.map(({ jwk, ...rest }) => ({ ...rest, publicKeyJwk: jwk })),
    lowValueCounters: server.lowValueCounters,
    currentTransaction: flow.transaction,
    scaDecision: flow.decision,
    challenge: flow.challenge
      ? { challenge: flow.challenge.challenge, canonical: flow.challenge.canonical, issuedAt: flow.challenge.issuedAt, expiresAt: flow.challenge.expiresAt }
      : null,
    visualConfirmationDisplayedAt: flow.displayedAt,
    ledger: server.ledger,
    log: auditLog,
  };
  const blob = new Blob([prettyJson(record)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sca-audit-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  log('info', 'Audit record exported');
}

// ------------------------------------------------------------------- gates

function refreshGates() {
  const hasCredential = server.credentials.length > 0;
  $('btn-assess').disabled = false;
  $('register-hint').textContent = hasCredential ? '' : '';
  document.querySelectorAll('#btn-auth-plain, #btn-auth-spc').forEach((b) => {
    b.disabled = !hasCredential;
    b.title = hasCredential ? '' : 'Enrol a passkey first (step 1).';
  });
}

// -------------------------------------------------------------------- init

async function init() {
  env = await probeEnvironment();
  server = new BankServer({
    rpId: env.rpId,
    rpName: 'Demo Bank (PSD2 SCA reference)',
    origin: env.origin,
    log,
  });

  renderEnvBadges();
  renderCredentials();
  renderCounters();
  renderLedger();
  refreshGates();

  log('info', `Relying party ${env.rpId} · origin ${env.origin}`);
  if (!env.secureContext) log('bad', 'Not a secure context — WebAuthn will refuse to run. Use HTTPS or localhost.');
  if (!env.platformAuthenticator) log('warn', 'No platform authenticator detected; a security key or a phone via hybrid transport can still be used.');
  if (!env.spc) log('info', 'Secure Payment Confirmation unavailable — the demo will use plain WebAuthn with a page-rendered confirmation.');

  $('payment-form').addEventListener('submit', onAssess);
  $('btn-register').addEventListener('click', onRegister);
  $('btn-export').addEventListener('click', exportAudit);
  $('btn-clear-log').addEventListener('click', () => {
    auditLog.length = 0;
    $('audit-log').innerHTML = '';
  });
  $('btn-reset').addEventListener('click', () => {
    if (!confirm('Forget enrolled passkeys, counters and the ledger held by this demo? Your device keeps its passkey — remove it in your password manager if you want it gone there too.')) return;
    server.reset();
    renderCredentials();
    renderCounters();
    renderLedger();
    ['step-sca', 'step-link', 'step-auth', 'step-verify'].forEach((id) => $(id).classList.add('is-idle'));
    resetSection('step-sca', 'sca-body', 'Submit a payment above to see the assessment.');
    resetSection('step-link', 'link-body', 'Waiting for an SCA decision.');
    resetSection('step-auth', 'auth-body', 'Waiting for a dynamically linked challenge.');
    resetSection('step-verify', 'verify-body', 'No authorisation attempted yet.');
    log('warn', 'Demo state reset');
  });
  $('btn-preset-low').addEventListener('click', () => {
    $('f-amount').value = '12.00';
    $('f-currency').value = 'EUR';
    $('payment-form').requestSubmit();
  });
  $('f-risk').addEventListener('input', (e) => {
    $('out-risk').textContent = e.target.value;
  });
  const syncRecurring = () => {
    $('c-first').disabled = !$('c-recurring').checked;
  };
  $('c-recurring').addEventListener('change', syncRecurring);
  syncRecurring();
}

init().catch((error) => {
  console.error(error);
  document.body.insertAdjacentHTML(
    'afterbegin',
    `<div class="wrap notice-bar"><p><strong>The demo failed to start.</strong> ${esc(String(error))}</p></div>`,
  );
});
