/**
 * UI orchestration for the three actions a payments portal asks a customer to
 * authorise: signing in, adding a beneficiary, and initiating a credit
 * transfer. Each one is a different regulatory question wearing the same
 * WebAuthn plumbing, so the flow below is shared and the differences live in
 * the SCENARIOS table.
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
import {
  ACCESS_EXEMPTION_DAYS,
  THRESHOLDS,
  assessAccess,
  assessBeneficiary,
  assessPayment,
} from './sca-engine.js';
import {
  authorisePlain,
  createPasskey,
  friendlyWebauthnError,
  probeEnvironment,
} from './client.js';
import { COSE_ALG, describeFlags } from './webauthn-codec.js';

const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const auditLog = [];
let env = null;
let server = null;

const flow = {
  scenario: 'login',
  subject: null,
  decision: null,
  challenge: null,
  displayedAt: null,
  lastAssertion: null,
  lastPayload: null,
};

const VOP_LABELS = {
  MATCH: { text: 'Name matches', tone: 'good' },
  CLOSE_MATCH: { text: 'Close match — review', tone: 'warn' },
  NO_MATCH: { text: 'No match — high risk', tone: 'bad' },
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
  list.scrollTop = list.scrollHeight;
}

// ---------------------------------------------------------------- scenarios

const SCENARIOS = {
  login: {
    formId: 'form-login',
    subtitle: 'Accessing the portal. SCA is in scope under PSD2 Art. 97(1)(a); RTS Art. 10 may exempt it.',
    // A sign-in has no amount and no payee, so there is nothing to bind.
    bind: false,
    exemptAction: 'Resume the session without SCA',
    tampering: null,
    readSubject() {
      return {
        schema: 'sca-rts-demo/access/1',
        type: 'login',
        subjectId: `SESS-${b64uEncode(crypto.getRandomValues(new Uint8Array(6)))}`,
        user: server.user.name,
        scope: $('f-scope').value,
        channel: 'web-portal',
        requestedAt: nowIso(),
      };
    },
    assess(subject) {
      return assessAccess({
        firstAccess: server.session.accessCount === 0,
        lastScaAt: server.session.lastScaAt,
        scope: subject.scope,
      });
    },
    confirmPanel(subject) {
      return `
        <span class="eyebrow">Confirm sign-in</span>
        <div>
          <div class="payee">${esc(server.user.displayName)}</div>
          <p class="to">${esc(subject.user)}</p>
        </div>
        <div class="meta">
          <span>${subject.scope === 'full-portal' ? 'Full portal access' : 'Read-only access'}</span>
          <span>${esc(subject.subjectId)}</span>
        </div>
        <p class="foot">There is no amount or payee to display here, so RTS Art. 5(1)(a) has nothing to bite on. What protects this step is the challenge being unpredictable, single-use and — the property SMS codes lack — bound to this origin.</p>`;
    },
    describe: (subject) => ({
      headline: 'Signed in',
      detail: subject.scope === 'full-portal' ? 'Full portal access' : 'Read-only access',
    }),
    success: () => 'The session is established, and the Article 10 window has been restarted from this authentication.',
  },

  beneficiary: {
    formId: 'form-beneficiary',
    subtitle: 'Adding a payee. SCA is in scope under PSD2 Art. 97(1)(c), and under RTS Art. 13(1) for the trusted list.',
    bind: true,
    exemptAction: null,
    tampering: (subject) => [
      { value: 'none', label: 'No tampering — honest submission' },
      { value: 'iban', label: 'Swap the IBAN after authorisation (the classic attack)' },
      { value: 'name', label: 'Change the beneficiary name' },
      // Only meaningful when there is a warning to suppress.
      ...(subject.vop.outcome === 'MATCH'
        ? []
        : [{ value: 'vop', label: 'Rewrite the Verification of Payee result to “match”' }]),
    ],
    readSubject() {
      const vop = $('b-vop').value;
      return {
        schema: 'sca-rts-demo/beneficiary/1',
        type: 'beneficiary',
        beneficiaryId: `BEN-${b64uEncode(crypto.getRandomValues(new Uint8Array(6)))}`,
        name: $('b-name').value.trim(),
        iban: $('b-iban').value.trim().toUpperCase(),
        country: $('b-country').value.trim().toUpperCase(),
        trusted: $('b-trusted').checked,
        vop: { outcome: vop, checkedAt: nowIso() },
        requestedAt: nowIso(),
      };
    },
    assess(subject) {
      return assessBeneficiary({ trusted: subject.trusted });
    },
    confirmPanel(subject) {
      const vop = VOP_LABELS[subject.vop.outcome];
      return `
        <span class="eyebrow">Confirm new beneficiary</span>
        <div>
          <div class="payee">${esc(subject.name)}</div>
          <p class="to">${esc(subject.iban)}</p>
        </div>
        <div class="chips">
          <span class="chip ${vop.tone === 'good' ? 'good' : vop.tone === 'warn' ? 'warn' : 'bad'}">Verification of Payee: ${esc(vop.text)}</span>
          <span class="chip">${esc(subject.country)}</span>
          ${subject.trusted ? '<span class="chip warn">Trusted beneficiary list</span>' : ''}
        </div>
        ${
          subject.vop.outcome !== 'MATCH'
            ? `<p class="foot warn-foot">The account name does not match the beneficiary name. Under Regulation (EU) 2024/886 the customer must be warned and may still proceed — so bind that warning into what they sign, and keep it as evidence of what they were shown.</p>`
            : ''
        }
        <p class="foot">Article 5 does not reach a non-payment action, but the name, IBAN and match result are committed to the challenge regardless. Change any of them after this point and the authorisation dies.</p>`;
    },
    applyTampering(subject, mode) {
      const clone = structuredClone(subject);
      if (mode === 'iban') clone.iban = 'LT601010012345678901';
      if (mode === 'name') clone.name = 'Acme Manufacturing Holdings Ltd';
      if (mode === 'vop') clone.vop = { ...clone.vop, outcome: 'MATCH' };
      return clone;
    },
    describe: (subject) => ({
      headline: `Beneficiary added — ${subject.name}`,
      detail: `${subject.iban} · VoP ${subject.vop.outcome}${subject.trusted ? ' · trusted' : ''}`,
    }),
    success: (subject) =>
      `${subject.name} was added with the IBAN and match result the customer actually saw${
        subject.trusted ? ', and placed on the trusted-beneficiary list — payments to it may now qualify for the Art. 13 exemption' : ''
      }.`,
  },

  payment: {
    formId: 'form-payment',
    subtitle: 'Initiating a credit transfer. SCA is in scope under PSD2 Art. 97(1)(b), with the Art. 13–18 exemptions in play.',
    bind: true,
    exemptAction: 'Execute without SCA (use the exemption)',
    tampering: [
      { value: 'none', label: 'No tampering — honest submission' },
      { value: 'amount', label: 'Change the amount (×100)' },
      { value: 'payee', label: 'Redirect to a different payee and IBAN' },
      { value: 'both', label: 'Change both amount and payee' },
      { value: 'reference', label: 'Change only the reference (not amount or payee)' },
    ],
    readSubject() {
      return {
        schema: 'sca-rts-demo/payment/1',
        type: 'payment',
        txnId: `TX-${b64uEncode(crypto.getRandomValues(new Uint8Array(6)))}`,
        amount: normaliseAmount($('f-amount').value),
        currency: $('f-currency').value,
        payee: { name: $('f-payee').value.trim(), iban: $('f-iban').value.trim().toUpperCase() },
        debtorAccount: 'IE64IRCE92050112345678',
        reference: $('f-reference').value.trim(),
        initiatedAt: nowIso(),
        channel: 'web-remote',
      };
    },
    assess(subject) {
      const selected = server.beneficiaries.find((b) => b.beneficiaryId === $('f-payee-select').value);
      return assessPayment(subject, {
        // Trusted status is earned in the beneficiary flow, not asserted here.
        trustedBeneficiary: Boolean(selected?.trusted),
        recurringMandate: $('c-recurring').checked,
        firstOfSeries: $('c-first').checked,
        sameOwnerSamePsp: $('c-self').checked,
        corporateProcess: $('c-corporate').checked,
        forceSca: $('c-force').checked,
        riskScore: Number($('f-risk').value),
        riskThreshold: 40,
        fraudRate: Number($('f-fraud').value),
        lowValueCounters: server.lowValueCounters,
      });
    },
    confirmPanel(subject) {
      return `
        <span class="eyebrow">Confirm this payment</span>
        <div>
          <div class="amount">${esc(formatMoney(subject.amount, subject.currency))}</div>
          <p class="to">to</p>
          <div class="payee">${esc(subject.payee.name)}</div>
        </div>
        <div class="meta">
          <span>${esc(subject.payee.iban)}</span>
          ${subject.reference ? `<span>ref ${esc(subject.reference)}</span>` : ''}
          <span>${esc(subject.txnId)}</span>
        </div>
        <p class="foot">Article 5(1)(a): the payer must be made aware of the amount and the payee before authenticating. Displayed at ${esc(
          flow.displayedAt,
        )} and recorded in the audit trail.</p>`;
    },
    applyTampering(subject, mode) {
      const clone = structuredClone(subject);
      if (mode === 'amount' || mode === 'both') clone.amount = normaliseAmount(Number(subject.amount) * 100);
      if (mode === 'payee' || mode === 'both') clone.payee = { name: 'Quick Cash Holdings Ltd', iban: 'LT601010012345678901' };
      if (mode === 'reference') clone.reference = 'ORDER-0001';
      return clone;
    },
    describe: (subject) => ({
      headline: formatMoney(subject.amount, subject.currency),
      detail: subject.payee.name,
    }),
    success: (subject) =>
      `The transaction credited to ${subject.payee.name} for ${formatMoney(
        subject.amount,
        subject.currency,
      )} is byte-for-byte the one the payer saw and signed.`,
  },
};

const current = () => SCENARIOS[flow.scenario];

function setScenario(name) {
  flow.scenario = name;
  flow.subject = null;
  flow.decision = null;
  flow.challenge = null;
  flow.lastAssertion = null;

  for (const button of document.querySelectorAll('#scenarios .scenario')) {
    button.setAttribute('aria-pressed', String(button.dataset.scenario === name));
  }
  for (const [key, scenario] of Object.entries(SCENARIOS)) {
    $(scenario.formId).hidden = key !== name;
  }
  $('subject-sub').textContent = SCENARIOS[name].subtitle;

  resetSection('step-sca', 'sca-body', 'Submit an action above to see the assessment.');
  resetSection('step-link', 'link-body', 'Waiting for an SCA decision.');
  resetSection('step-auth', 'auth-body', 'Waiting for a challenge.');
  resetSection('step-verify', 'verify-body', 'No authorisation attempted yet.');
  if (name === 'payment') renderPayeeOptions();
}

function resetSection(sectionId, bodyId, placeholder) {
  $(sectionId).classList.add('is-idle');
  $(bodyId).innerHTML = `<p class="placeholder">${esc(placeholder)}</p>`;
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
      log('warn', 'Credential removed from the registry — in a real portal this is the offboarding path, and it must also close active sessions');
      renderCredentials();
      refreshGates();
    });
  });
}

/**
 * Enrolment retry ladder.
 *
 * A browser that will not accept one of the optional parts of the request
 * throws NotSupportedError before any prompt is shown, so stepping down costs
 * the customer nothing — and the step that succeeds tells us exactly what their
 * stack supports. The SPC `payment` extension is the usual culprit: the Secure
 * Payment Confirmation specification requires create() to throw
 * NotSupportedError on a user agent with no SPC implementation, which would
 * otherwise block enrolment outright rather than merely disabling SPC.
 */
function registrationVariants() {
  const variants = [];
  if (env.paymentRequest) {
    variants.push({ note: 'ES256/EdDSA/RS256 with the SPC payment extension', tuning: { payment: true } });
  }
  variants.push({ note: 'ES256/EdDSA/RS256, no payment extension', tuning: { payment: false } });
  variants.push({
    note: 'ES256 and RS256 only',
    tuning: { payment: false, algorithms: [COSE_ALG.ES256, COSE_ALG.RS256] },
  });
  variants.push({ note: 'ES256 only', tuning: { payment: false, algorithms: [COSE_ALG.ES256] } });
  return variants;
}

async function onRegister() {
  const button = $('btn-register');
  button.disabled = true;
  $('register-hint').textContent = 'Follow your device prompt…';
  try {
    let credential = null;
    let accepted = null;
    let lastError = null;

    for (const variant of registrationVariants()) {
      const options = server.beginRegistration(variant.tuning);
      log('step', `POST /webauthn/register/begin → ${variant.note}`, {
        rpId: options.rp.id,
        userVerification: options.authenticatorSelection.userVerification,
        algs: options.pubKeyCredParams.map((param) => param.alg),
        extensions: Object.keys(options.extensions),
      });
      try {
        credential = await createPasskey(options);
        accepted = variant;
        break;
      } catch (error) {
        lastError = error;
        // Only a parameter refusal is worth retrying. A cancellation, a
        // duplicate credential or a bad origin means stop and say so.
        if (error?.name !== 'NotSupportedError') throw error;
        log('warn', `Refused (${variant.note}) — stepping down and retrying`, error.message || error.name);
      }
    }

    if (!credential) throw lastError ?? new Error('No registration variant was accepted.');

    const result = await server.finishRegistration(credential);
    $('reg-result').innerHTML = renderChecklist(result.checks);
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
    $('reg-result').innerHTML = `<div class="verdict fail">
      <span class="icon">✗</span>
      <div>
        <h3>Registration failed</h3>
        <p>${esc(friendlyWebauthnError(error))}</p>
        <p class="hint">Every fallback was tried: ${esc(registrationVariants().map((v) => v.note).join('; '))}. This browser reports secure context ${
          env.secureContext ? 'yes' : 'no'
        }, platform authenticator ${env.platformAuthenticator ? 'yes' : 'no'}, origin ${esc(env.origin)}.</p>
      </div>
    </div>`;
  } finally {
    button.disabled = false;
    $('register-hint').textContent = '';
  }
}

// ----------------------------------------------------------------- step 2

function renderPayeeOptions() {
  const select = $('f-payee-select');
  const saved = server.beneficiaries;
  const previous = select.value;
  select.innerHTML = [
    '<option value="">New payee — entered by hand</option>',
    ...saved.map(
      (b) =>
        `<option value="${esc(b.beneficiaryId)}">${esc(b.name)} · ${esc(b.iban.slice(0, 8))}…${
          b.trusted ? ' · trusted' : ''
        }</option>`,
    ),
  ].join('');
  select.value = saved.some((b) => b.beneficiaryId === previous) ? previous : '';
  applyPayeeSelection();
}

function applyPayeeSelection() {
  const selected = server.beneficiaries.find((b) => b.beneficiaryId === $('f-payee-select').value);
  const name = $('f-payee');
  const iban = $('f-iban');
  if (selected) {
    name.value = selected.name;
    iban.value = selected.iban;
    name.readOnly = true;
    iban.readOnly = true;
  } else {
    name.readOnly = false;
    iban.readOnly = false;
  }
}

function onSubmit(event) {
  event.preventDefault();
  const scenario = current();
  const subject = scenario.readSubject();
  const decision = scenario.assess(subject);

  flow.subject = subject;
  flow.decision = decision;
  flow.challenge = null;
  flow.lastAssertion = null;

  const described = scenario.describe(subject);
  log('step', `POST /actions/${subject.type} → ${described.headline}${described.detail ? ` · ${described.detail}` : ''}`);
  log(decision.scaRequired ? 'info' : 'warn', decision.summary);

  renderDecision(decision, subject);
  resetSection('step-link', 'link-body', 'Waiting for an SCA decision.');
  resetSection('step-auth', 'auth-body', 'Waiting for a challenge.');
  resetSection('step-verify', 'verify-body', 'No authorisation attempted yet.');
  $('step-sca').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ----------------------------------------------------------------- step 3

function renderDecision(decision, subject) {
  $('step-sca').classList.remove('is-idle');
  const scenario = current();

  const verdictClass = decision.scaRequired ? 'sca' : 'exempt';
  const icon = decision.scaRequired ? '🔐' : '⚡';

  const fx =
    decision.indicativeFx
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
    ? '<button type="button" class="btn primary" id="btn-proceed-sca">Generate challenge and authenticate</button>'
    : `<div class="row">
         <button type="button" class="btn" id="btn-execute-exempt">${esc(scenario.exemptAction)}</button>
         <button type="button" class="btn primary" id="btn-proceed-sca">Authenticate anyway</button>
       </div>
       <p class="hint">A PSP may always choose to authenticate. For payments, the payee’s PSP can also refuse an exemption and send the transaction back for SCA.</p>`;

  $('sca-body').innerHTML = `
    <div class="verdict ${verdictClass}">
      <span class="icon">${icon}</span>
      <div>
        <h3>${decision.scaRequired ? 'Strong customer authentication required' : 'Exemption available'}</h3>
        <p>${esc(decision.summary)}</p>
      </div>
    </div>
    <div class="basis">
      <span class="basis-art">${esc(decision.basis.article)}</span>
      <span>${esc(decision.basis.text)}</span>
    </div>
    ${fx}
    <ul class="exemptions">${rows}</ul>
    ${actions}`;

  $('btn-proceed-sca')?.addEventListener('click', () => beginAuthorisation(subject, decision));
  $('btn-execute-exempt')?.addEventListener('click', () => executeExempt(subject, decision));
}

function executeExempt(subject, decision) {
  const entry = server.applyExempt(subject, decision, decision.amountEur ?? 0);
  log('warn', `Carried out without SCA under ${decision.chosenExemption.article} — ${decision.chosenExemption.name}`, {
    subjectId: subject.subjectId ?? subject.txnId,
  });
  renderPortalState();
  renderCounters();
  renderLedger();
  $('sca-body').insertAdjacentHTML(
    'beforeend',
    `<div class="verdict exempt"><span class="icon">✓</span><div><h3>Action #${entry.sequence} completed under an exemption</h3><p>No authentication code was generated, so Article 5 dynamic linking did not apply. ${
      subject.type === 'login'
        ? 'Note that an exempted access does not restart the Article 10 window — that runs from the last actual SCA.'
        : 'The Article 16 counters on the right have moved.'
    }</p></div></div>`,
  );
}

// ----------------------------------------------------------------- step 4

async function beginAuthorisation(subject, decision) {
  const scenario = current();
  const challenge = await server.createAuthorisationChallenge(subject, { scaDecision: decision, bind: scenario.bind });
  flow.challenge = challenge;
  flow.displayedAt = nowIso();

  log(
    'step',
    scenario.bind
      ? 'POST /sca/begin → challenge = SHA-256(nonce ‖ canonical-JSON(action))'
      : 'POST /sca/begin → challenge = 32 random bytes (nothing to bind)',
    { challenge: challenge.challenge },
  );

  renderBinding(subject, challenge);
  renderAuthorise(subject, challenge);
  $('step-link').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderBinding(subject, challenge) {
  const scenario = current();
  $('step-link').classList.remove('is-idle');

  const derivation = challenge.canonical
    ? `<div class="stack">
         <div class="label-row"><h3>Canonical action</h3><span class="tag">${challenge.canonical.length} bytes hashed</span></div>
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
         <p class="hint">The nonce and the authoritative record stay on the server. The browser only ever sees the 32-byte challenge — which is exactly why the server has to re-hash at verification time rather than trust what comes back.</p>
       </div>`
    : `<div class="stack">
         <div class="label-row"><h3>Challenge</h3><span class="tag">unbound — 32 random bytes</span></div>
         <dl class="kv">
           <dt>challenge</dt><dd>${esc(challenge.challenge)}</dd>
           <dt>expires</dt><dd>${esc(new Date(challenge.expiresAt).toISOString())}</dd>
         </dl>
         <p class="hint">No commitment is computed because a sign-in has no amount or payee. The scope of the session is decided by the server from its own records — never from anything the client submits — so there is nothing for an attacker to rewrite in transit.</p>
       </div>`;

  $('link-body').innerHTML = `
    <div class="confirm" id="confirm-panel">${scenario.confirmPanel(subject)}</div>
    ${derivation}`;
}

// ----------------------------------------------------------------- step 5

function renderAuthorise(subject, challenge) {
  const scenario = current();
  $('step-auth').classList.remove('is-idle');

  const modes = typeof scenario.tampering === 'function' ? scenario.tampering(subject) : scenario.tampering;
  const attack = modes
    ? `<div class="attack">
         <h3>Attacker simulation</h3>
         <p>Tamper with the action <em>after</em> the customer authorised it — the manipulated payload is what gets submitted, while the signature still covers the original challenge.</p>
         <select id="tamper-mode" aria-label="Tampering to apply after authorisation">
           ${modes.map((t) => `<option value="${esc(t.value)}">${esc(t.label)}</option>`).join('')}
         </select>
       </div>`
    : `<div class="attack">
         <h3>Nothing to tamper with</h3>
         <p>An unbound challenge cannot detect a rewritten payload — there is no commitment to compare against. For a sign-in that is fine, because the server decides the session’s scope from its own records rather than from the request. The moment an action carries an amount or a payee, that stops being true and binding becomes necessary.</p>
       </div>`;

  $('auth-body').innerHTML = `
    ${attack}
    <div class="row">
      <button type="button" class="btn primary" id="btn-auth-plain">Authorise with passkey</button>
      <button type="button" class="btn ghost" id="btn-replay" disabled>Replay the last authorisation</button>
    </div>
    <p class="hint">Compare with an SMS code: it would be equally valid typed into a lookalike domain, read out over the phone, or intercepted after a SIM swap. This assertion is useless anywhere but ${esc(env.origin)}.</p>`;

  $('btn-auth-plain').addEventListener('click', () => authorise(subject, challenge));
  $('btn-replay').addEventListener('click', () => replay());
  refreshGates();
}

async function authorise(subject, challenge) {
  const scenario = current();
  const button = $('btn-auth-plain');
  button.disabled = true;

  try {
    log('step', 'navigator.credentials.get() — userVerification: required');
    const { assertion } = await authorisePlain({
      challengeBytes: challenge.challengeBytes,
      allowCredentials: challenge.allowCredentials,
      rpId: challenge.rpId,
      timeout: challenge.timeout,
    });

    const mode = $('tamper-mode')?.value ?? 'none';
    const executionPayload = mode === 'none' || !scenario.applyTampering ? subject : scenario.applyTampering(subject, mode);
    if (executionPayload !== subject) {
      log('bad', `Attacker rewrote the payload after authorisation (${mode})`, diffTransactions(subject, executionPayload));
    }

    flow.lastAssertion = assertion;
    flow.lastPayload = executionPayload;
    $('btn-replay').disabled = false;

    await verify(assertion, executionPayload);
  } catch (error) {
    log('bad', `Authorisation failed — ${friendlyWebauthnError(error)}`);
    $('step-verify').classList.remove('is-idle');
    $('verify-body').innerHTML = `<div class="verdict fail"><span class="icon">✗</span><div><h3>No assertion produced</h3><p>${esc(
      friendlyWebauthnError(error),
    )}</p></div></div>`;
  } finally {
    button.disabled = false;
  }
}

async function replay() {
  if (!flow.lastAssertion) return;
  log('step', 'Replaying the previous assertion — the challenge has already been consumed');
  await verify(flow.lastAssertion, flow.lastPayload, { replay: true });
}

// ----------------------------------------------------------------- step 6

async function verify(assertion, executionPayload, { replay = false } = {}) {
  const result = await server.verifyAuthorisation({ assertion, executionPayload });
  renderVerification(result, executionPayload, replay);

  if (result.ok) {
    log('good', `Authorisation accepted — action #${result.receipt.sequence} carried out`, {
      type: executionPayload.type,
    });
  } else {
    const failed = result.checks.filter((c) => c.status === STATUS.FAIL).map((c) => c.label);
    log('bad', `Authorisation rejected — ${failed.length} check(s) failed`, failed);
  }
  renderPortalState();
  renderCounters();
  renderLedger();
  if (flow.scenario === 'payment') renderPayeeOptions();
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

function renderVerification(result, executionPayload, replayed) {
  $('step-verify').classList.remove('is-idle');
  const scenario = SCENARIOS[executionPayload.type] ?? SCENARIOS[flow.scenario];

  const failedLinking = result.checks.find((c) => c.id === 'dynamic-linking' && c.status === STATUS.FAIL);
  const verdict = result.ok
    ? `<div class="verdict ok"><span class="icon">✓</span><div><h3>${esc(
        scenario.describe(executionPayload).headline,
      )}</h3><p>${esc(scenario.success(executionPayload))}</p></div></div>`
    : `<div class="verdict fail"><span class="icon">✗</span><div><h3>Authorisation rejected — nothing carried out</h3><p>${
        replayed
          ? 'The assertion is cryptographically valid, but its challenge was already consumed. An authentication code may not be reusable (Art. 4(3)(a)).'
          : failedLinking
            ? 'The signature verifies, but what was submitted does not re-hash to the challenge the customer signed. This is the binding doing its job.'
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
      <div class="label-row"><h3>clientDataJSON (signed)</h3><span class="tag">${esc(result.clientData.type)}</span></div>
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
      <div class="label-row"><h3>Submitted for execution</h3><span class="tag">what the server was asked to do</span></div>
      <pre class="codeblock wrap-any">${esc(canonicalJson(executionPayload))}</pre>
    </div>
    <div class="row">
      <button type="button" class="btn" id="btn-new-challenge">Issue a fresh challenge and retry</button>
    </div>`;

  $('btn-new-challenge').addEventListener('click', () => {
    if (flow.subject && flow.decision) beginAuthorisation(flow.subject, flow.decision);
  });
}

// ------------------------------------------------------------------- rail

function renderPortalState() {
  const { session } = server;
  const days = session.lastScaAt ? Math.floor((Date.now() - session.lastScaAt) / 86_400_000) : null;
  const beneficiaries = server.beneficiaries;

  $('portal-state').innerHTML = `
    <dl class="kv">
      <dt>Session</dt><dd>${session.signedInAt ? 'signed in' : 'not signed in'}</dd>
      <dt>Last SCA</dt><dd>${days === null ? 'never' : `${days} day(s) ago`}</dd>
      <dt>Art. 10 window</dt><dd>${
        days === null ? 'not started' : days <= ACCESS_EXEMPTION_DAYS ? `${ACCESS_EXEMPTION_DAYS - days} day(s) left` : 'expired'
      }</dd>
      <dt>Accesses</dt><dd>${session.accessCount}</dd>
    </dl>
    ${
      beneficiaries.length
        ? `<div class="stack"><div class="label-row"><h3>Beneficiaries</h3></div>${beneficiaries
            .map(
              (b) =>
                `<div class="ledger-item"><div class="top"><span class="amt">${esc(b.name)}</span>${
                  b.trusted ? '<span class="chip warn">trusted</span>' : ''
                }</div><span class="meta">${esc(b.iban)} · VoP ${esc(b.vop.outcome)}</span></div>`,
            )
            .join('')}</div>`
        : '<p class="hint">No beneficiaries yet. Add one to unlock the Article 13 exemption in the payment flow.</p>'
    }`;
}

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

/**
 * Ledger entries can outlive the shape that wrote them — state persists in
 * localStorage across deploys. Never let an unrecognised entry take the page
 * down with it.
 */
function describeEntry(entry) {
  const scenario = SCENARIOS[entry?.kind];
  if (scenario) {
    try {
      return scenario.describe(entry.subject ?? {});
    } catch {
      /* fall through to the generic description */
    }
  }
  return { headline: 'Earlier action', detail: entry?.subject?.payee?.name ?? entry?.kind ?? '' };
}

function renderLedger() {
  const entries = server.ledger.slice(0, 8);
  if (!entries.length) {
    $('ledger').innerHTML = '<p class="placeholder">Nothing yet.</p>';
    return;
  }
  $('ledger').innerHTML = entries
    .map((e) => {
      const described = describeEntry(e);
      return `<div class="ledger-item">
        <div class="top">
          <span class="amt">${esc(described.headline)}</span>
          <span class="chip ${e.authenticated ? 'good' : 'warn'}">${
            e.authenticated ? 'SCA' : esc(e.exemption?.article ?? 'exempt')
          }</span>
        </div>
        <span>${esc(described.detail)}</span>
        <span class="meta">#${e.sequence} · ${esc(e.executedAt)}</span>
      </div>`;
    })
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
    session: server.session,
    beneficiaries: server.beneficiaries,
    lowValueCounters: server.lowValueCounters,
    currentAction: flow.subject,
    scaDecision: flow.decision,
    challenge: flow.challenge
      ? {
          challenge: flow.challenge.challenge,
          bound: flow.challenge.bound,
          canonical: flow.challenge.canonical,
          issuedAt: flow.challenge.issuedAt,
          expiresAt: flow.challenge.expiresAt,
        }
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
  const button = $('btn-auth-plain');
  if (button) {
    button.disabled = !hasCredential;
    button.title = hasCredential ? '' : 'Enrol a passkey first (step 1).';
  }
}

// -------------------------------------------------------------------- init

function renderEnvBadges() {
  const items = [
    { ok: env.secureContext, label: `secure context: ${env.secureContext ? 'yes' : 'no'}` },
    { ok: true, label: `rpId: ${env.rpId}`, neutral: true },
    { ok: env.webauthn, label: `WebAuthn: ${env.webauthn ? 'available' : 'missing'}` },
    { ok: env.platformAuthenticator, label: `platform authenticator: ${env.platformAuthenticator ? 'yes' : 'no'}`, warnIfNo: true },
    { ok: env.conditionalMediation, label: `passkey autofill: ${env.conditionalMediation ? 'yes' : 'no'}`, warnIfNo: true },
  ];
  $('env-badges').innerHTML = items
    .map((item) => `<li class="${item.neutral ? '' : item.ok ? 'ok' : item.warnIfNo ? 'warn' : 'no'}">${esc(item.label)}</li>`)
    .join('');
}

function resetDemo() {
  server.reset();
  renderCredentials();
  renderPortalState();
  renderCounters();
  renderLedger();
  setScenario(flow.scenario);
  log('warn', 'Demo state reset');
}

async function init() {
  env = await probeEnvironment();
  server = new BankServer({
    rpId: env.rpId,
    rpName: 'Demo Payments Portal (PSD2 SCA reference)',
    origin: env.origin,
    log,
  });

  renderEnvBadges();
  renderCredentials();
  renderPortalState();
  renderCounters();
  renderLedger();

  $('access-window').textContent = String(ACCESS_EXEMPTION_DAYS);
  $('login-name').textContent = server.user.displayName;
  $('login-email').textContent = server.user.name;

  log('info', `Relying party ${env.rpId} · origin ${env.origin}`);
  if (!env.secureContext) log('bad', 'Not a secure context — WebAuthn will refuse to run. Use HTTPS or localhost.');
  if (!env.platformAuthenticator) log('warn', 'No platform authenticator detected; a security key or a phone via hybrid transport can still be used.');

  for (const button of document.querySelectorAll('#scenarios .scenario')) {
    button.addEventListener('click', () => setScenario(button.dataset.scenario));
  }
  for (const scenario of Object.values(SCENARIOS)) {
    $(scenario.formId).addEventListener('submit', onSubmit);
  }

  $('btn-register').addEventListener('click', onRegister);
  $('btn-export').addEventListener('click', exportAudit);
  $('btn-clear-log').addEventListener('click', () => {
    auditLog.length = 0;
    $('audit-log').innerHTML = '';
  });
  $('btn-reset').addEventListener('click', () => {
    if (!confirm('Forget enrolled passkeys, beneficiaries, counters and activity held by this demo? Your device keeps its passkey — remove it in your password manager if you want it gone there too.')) return;
    resetDemo();
  });
  $('btn-age-sca').addEventListener('click', () => {
    server.ageLastSca(200);
    renderPortalState();
    log('info', 'Simulated 200 days passing since the last SCA — the Article 10 window has now lapsed');
  });
  $('btn-preset-low').addEventListener('click', () => {
    $('f-amount').value = '12.00';
    $('f-currency').value = 'EUR';
    $('form-payment').requestSubmit();
  });
  $('f-risk').addEventListener('input', (e) => {
    $('out-risk').textContent = e.target.value;
  });
  $('f-payee-select').addEventListener('change', applyPayeeSelection);
  const syncRecurring = () => {
    $('c-first').disabled = !$('c-recurring').checked;
  };
  $('c-recurring').addEventListener('change', syncRecurring);
  syncRecurring();

  setScenario('login');
}

init().catch((error) => {
  console.error(error);
  document.body.insertAdjacentHTML(
    'afterbegin',
    `<div class="wrap notice-bar">
      <p>
        <strong>The demo failed to start.</strong> ${esc(String(error))}
        <br>This is almost always state left by an earlier version of the demo.
        <button type="button" class="btn tiny ghost" id="btn-recover" style="margin-top:8px">Clear stored demo state and reload</button>
      </p>
    </div>`,
  );
  document.getElementById('btn-recover')?.addEventListener('click', () => {
    try {
      localStorage.removeItem('sca-rts-demo/bank-state/v1');
    } catch {
      /* nothing more we can do */
    }
    location.reload();
  });
});
