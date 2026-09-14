/**
 * End-to-end test of the demo using Chromium's virtual authenticator, so the
 * whole passkey flow — registration, assertion, signature verification,
 * dynamic linking, replay rejection — runs without touching real hardware.
 *
 *   npm install --no-save playwright
 *   npx playwright install chromium
 *   node tests/e2e.mjs
 *
 * Set BASE_URL to test a deployed copy instead of the bundled static server.
 */

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.json': 'application/json',
};

async function startStaticServer() {
  const server = createServer(async (req, res) => {
    const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    const file = join(ROOT, normalize(path === '/' ? '/index.html' : path).replace(/^(\.\.[/\\])+/, ''));
    try {
      const body = await readFile(file);
      res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' });
      res.end(body);
    } catch {
      res.writeHead(404).end('not found');
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  // "localhost" rather than the loopback IP: an IP address is not a valid
  // WebAuthn relying-party ID, and it is a secure context either way.
  return { server, url: `http://localhost:${server.address().port}/` };
}

let failures = 0;
const check = (name, condition, extra = '') => {
  if (!condition) failures += 1;
  console.log(`${condition ? 'ok  ' : 'FAIL'}  ${name}${extra && !condition ? ` — ${extra}` : ''}`);
};
/** Wait for a *fresh* verification report, identified by text unique to it. */
const awaitReport = (page, needle) =>
  page.waitForFunction(
    (text) => document.querySelector('#verify-body')?.textContent?.includes(text) ?? false,
    needle,
    { timeout: 20000 },
  );

const cells = (page, selector) =>
  page.locator(selector).evaluateAll((els) =>
    els.map((el) => ({
      state: el.className,
      label: el.querySelector('.label')?.textContent ?? '',
      detail: el.querySelector('.detail')?.textContent ?? '',
    })),
  );

const started = process.env.BASE_URL ? { server: null, url: process.env.BASE_URL } : await startStaticServer();
const BASE = started.url;

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
const pageErrors = [];
page.on('pageerror', (error) => pageErrors.push(error.message));
page.on('console', (message) => {
  if (message.type() === 'error') pageErrors.push(message.text());
});

const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
const AUTHENTICATOR = {
  protocol: 'ctap2',
  ctap2Version: 'ctap2_1',
  transport: 'internal',
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
};
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: AUTHENTICATOR });

await page.goto(BASE, { waitUntil: 'networkidle' });

// --- enrolment -------------------------------------------------------------
await page.click('#btn-register');
await page.waitForSelector('.cred h3', { timeout: 20000 });
check('registration passes every server check', (await cells(page, '#reg-result .checklist li')).every((c) => c.state === 'pass'));
check(
  'authenticator holds exactly one credential',
  (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials.length === 1,
);

// --- 1. sign in ------------------------------------------------------------
const scenario = (name) => page.click(`#scenarios .scenario[data-scenario="${name}"]`);

await scenario('login');
await page.selectOption('#f-scope', 'full-portal');
await page.click('#form-login button[type="submit"]');
await page.waitForSelector('#btn-proceed-sca');
check('first sign-in requires SCA', /required/i.test(await page.locator('#sca-body .verdict h3').textContent()));

await page.click('#btn-proceed-sca');
await page.waitForSelector('#confirm-panel');
check('an unbound challenge is labelled as such', /unbound/.test(await page.locator('#link-body').innerText()));
check('no tamper control is offered for a sign-in', (await page.locator('#tamper-mode').count()) === 0);

await page.click('#btn-auth-plain');
await awaitReport(page, 'Signed in');
const loginChecks = await cells(page, '#verify-body .checklist li');
check('sign-in passes every check', loginChecks.every((c) => c.state !== 'fail'), JSON.stringify(loginChecks.filter((c) => c.state === 'fail')));
check(
  'dynamic linking is reported as not applicable, not as a pass',
  loginChecks.some((c) => /not applicable/.test(c.label) && c.state === 'skip'),
);
check('the Art. 10 window opens after SCA', /day\(s\) left/.test(await page.locator('#portal-state').innerText()));

// read-only re-access is now exempt under Art. 10
await page.selectOption('#f-scope', 'account-information');
await page.click('#form-login button[type="submit"]');
await page.waitForSelector('#sca-body .verdict');
check('read-only re-access is exempt under Art. 10', /Exemption available/i.test(await page.locator('#sca-body .verdict h3').textContent()));

// a session that can move money never is
await page.selectOption('#f-scope', 'full-portal');
await page.click('#form-login button[type="submit"]');
await page.waitForSelector('#sca-body .verdict');
check('a full-portal session is never exempt', /required/i.test(await page.locator('#sca-body .verdict h3').textContent()));

// and the window lapses
await page.selectOption('#f-scope', 'account-information');
await page.click('#btn-age-sca');
await page.click('#form-login button[type="submit"]');
await page.waitForSelector('#sca-body .verdict');
check('an expired Art. 10 window brings SCA back', /required/i.test(await page.locator('#sca-body .verdict h3').textContent()));

// --- 2. add a beneficiary --------------------------------------------------
await scenario('beneficiary');
await page.check('#b-trusted');
await page.click('#form-beneficiary button[type="submit"]');
await page.waitForSelector('#btn-proceed-sca');
check('adding a beneficiary always requires SCA', /required/i.test(await page.locator('#sca-body .verdict h3').textContent()));
check('no exemption is offered for a beneficiary change', (await page.locator('#btn-execute-exempt').count()) === 0);
check(
  'Art. 13 is explained as requiring SCA rather than exempting it',
  /requires\* SCA|requires SCA to add/.test(await page.locator('#sca-body').innerText()),
  await page.locator('#sca-body .exemptions').innerText(),
);

await page.click('#btn-proceed-sca');
await page.waitForSelector('#confirm-panel');
const beneficiaryPanel = await page.locator('#confirm-panel').innerText();
check('the IBAN is shown before authenticating', /DE89370400440532013000/.test(beneficiaryPanel));
check('the Verification of Payee result is shown', /Verification of Payee/.test(beneficiaryPanel));

// the classic attack: swap the IBAN after the customer approved it
await page.selectOption('#tamper-mode', 'iban');
await page.click('#btn-auth-plain');
await awaitReport(page, 'LT601010012345678901');
const ibanSwap = await cells(page, '#verify-body .checklist li');
check('a swapped IBAN is rejected', ibanSwap.some((c) => /re-hash/.test(c.label) && c.state === 'fail'));
check('the signature over the swapped payload still verifies', ibanSwap.some((c) => /Signature verifies/.test(c.label) && c.state === 'pass'));

// a no-match result must be shown, and rewriting it afterwards must be caught
await scenario('beneficiary');
await page.selectOption('#b-vop', 'NO_MATCH');
await page.click('#form-beneficiary button[type="submit"]');
await page.waitForSelector('#btn-proceed-sca');
await page.click('#btn-proceed-sca');
await page.waitForSelector('#tamper-mode');
check('a no-match result is surfaced to the customer', /does not match/.test(await page.locator('#confirm-panel').innerText()));
await page.selectOption('#tamper-mode', 'vop');
await page.click('#btn-auth-plain');
await awaitReport(page, 'NO_MATCH');
check('a rewritten Verification of Payee result is rejected', (await cells(page, '#verify-body .checklist li')).some((c) => /re-hash/.test(c.label) && c.state === 'fail'));

// honest submission
await scenario('beneficiary');
await page.selectOption('#b-vop', 'MATCH');
await page.click('#form-beneficiary button[type="submit"]');
await page.waitForSelector('#btn-proceed-sca');
await page.click('#btn-proceed-sca');
await page.waitForSelector('#tamper-mode');
await page.selectOption('#tamper-mode', 'none');
await page.click('#btn-auth-plain');
await awaitReport(page, 'Beneficiary added');
check('the beneficiary is stored', /Acme Manufacturing GmbH/.test(await page.locator('#portal-state').innerText()));

// --- 3. payment ------------------------------------------------------------
await scenario('payment');
check('the stored beneficiary is selectable as a payee', (await page.locator('#f-payee-select option').count()) > 1);

// ad-hoc payee: SCA required
await page.click('#btn-assess');
await page.waitForSelector('#btn-proceed-sca');
check('a €150 payment to a new payee requires SCA', /required/i.test(await page.locator('#sca-body .verdict h3').textContent()));

await page.click('#btn-proceed-sca');
await page.waitForSelector('#confirm-panel');
check('Art. 5(1)(a) panel shows the amount', (await page.locator('#confirm-panel .amount').textContent()).includes('150'));
check('Art. 5(1)(a) panel shows the payee', (await page.locator('#confirm-panel .payee').textContent()).includes('Merchant XYZ Ltd'));
check('no SPC button when the browser cannot do it', (await page.locator('#btn-auth-spc').count()) === 0);
check(
  'the page explains why the confirmation is only page-rendered',
  /only as trustworthy as the page/.test(await page.locator('#auth-body').innerText()),
  await page.locator('#auth-body').innerText(),
);

await page.selectOption('#tamper-mode', 'none');
await page.click('#btn-auth-plain');
await awaitReport(page, 'Merchant XYZ Ltd');
const honest = await cells(page, '#verify-body .checklist li');
check('honest payment passes every check', honest.every((c) => c.state !== 'fail'), JSON.stringify(honest.filter((c) => c.state === 'fail')));
check('signature verifies', honest.some((c) => /Signature verifies/.test(c.label) && c.state === 'pass'));
check('UV flag is asserted and checked', honest.some((c) => /UV flag set/.test(c.label) && c.state === 'pass'));
check('dynamic linking holds', honest.some((c) => /re-hash/.test(c.label) && c.state === 'pass'));

// replay
await page.click('#btn-replay');
await awaitReport(page, 'already been consumed');
check('replayed assertion is rejected', (await cells(page, '#verify-body .checklist li')).some((c) => /still open/.test(c.label) && c.state === 'fail'));

// tampering
for (const [mode, needle] of [['amount', '15000.00'], ['payee', 'Quick Cash Holdings']]) {
  await page.click('#btn-new-challenge');
  await page.waitForSelector('#tamper-mode');
  await page.selectOption('#tamper-mode', mode);
  await page.click('#btn-auth-plain');
  await awaitReport(page, needle);
  const rows = await cells(page, '#verify-body .checklist li');
  check(`tampered ${mode} breaks dynamic linking`, rows.some((c) => /re-hash/.test(c.label) && c.state === 'fail'));
  check(`tampered ${mode} still carries a valid signature`, rows.some((c) => /Signature verifies/.test(c.label) && c.state === 'pass'));
  check(`tampered ${mode} is reported in the field diff`, rows.some((c) => c.state === 'fail' && c.detail.includes(needle)), JSON.stringify(rows.filter((c) => c.state === 'fail')));
}

// the trusted beneficiary added in flow 2 now unlocks Art. 13
await page.selectOption('#f-payee-select', { index: 1 });
await page.click('#btn-assess');
await page.waitForSelector('#sca-body .verdict');
check('paying the trusted beneficiary is exempt under Art. 13', /Art. 13/.test(await page.locator('#sca-body .verdict p').textContent()), await page.locator('#sca-body .verdict p').textContent());

// a PSP may authenticate anyway
await page.check('#c-force');
await page.click('#btn-assess');
await page.waitForSelector('#sca-body .verdict');
check('a PSP may authenticate despite an available exemption', /PSP choice/i.test(await page.locator('#sca-body .verdict p').textContent()));
await page.uncheck('#c-force');

// --- Article 16 counters ---------------------------------------------------
await page.selectOption('#f-payee-select', { index: 0 });
await page.selectOption('#f-fraud', '0.30'); // take TRA off the table
await page.click('#btn-preset-low');
await page.waitForSelector('#btn-execute-exempt', { timeout: 15000 });
check('a €12 payment finds an exemption', /Exemption available/i.test(await page.locator('#sca-body .verdict h3').textContent()));
await page.click('#btn-execute-exempt');
await page.waitForSelector('#sca-body .verdict.exempt .icon');
check('Art. 16 counters advance', /€12\.00 of €100/.test(await page.locator('#counters').innerText()));

for (let i = 0; i < 10; i += 1) {
  await page.click('#btn-preset-low');
  await page.waitForSelector('#sca-body .verdict');
  if (!(await page.locator('#btn-execute-exempt').count())) break;
  await page.click('#btn-execute-exempt');
  await page.waitForSelector('#sca-body .verdict.exempt .icon');
}
check('exhausted Art. 16 counters bring SCA back', /required/i.test(await page.locator('#sca-body .verdict h3').textContent()));

// --- enrolment on a browser with no PaymentRequest -------------------------
// The SPC `payment` extension makes create() throw NotSupportedError on a user
// agent without SPC, so the request must not carry it there.
// A separate context so it starts with empty storage and its own authenticator.
const bareContext = await browser.newContext();
const bare = await bareContext.newPage();
bare.on('pageerror', (error) => pageErrors.push(error.message));
const bareCdp = await bareContext.newCDPSession(bare);
await bareCdp.send('WebAuthn.enable');
await bareCdp.send('WebAuthn.addVirtualAuthenticator', { options: AUTHENTICATOR });
await bare.addInitScript(() => {
  delete window.PaymentRequest;
});
await bare.goto(BASE, { waitUntil: 'networkidle' });
await bare.click('#btn-register');
await bare.waitForSelector('.cred h3', { timeout: 20000 });
const bareLog = await bare.locator('#audit-log').innerText();
check('enrols on a browser without PaymentRequest', /no payment extension/.test(bareLog), bareLog.slice(0, 300));
check('SPC extension is omitted rather than retried into', !/with the SPC payment extension/.test(bareLog));
await bareContext.close();

// --- Secure Payment Confirmation step-up -----------------------------------
// Headless Chromium reports SPC as unavailable; the step-up path is driven
// below with a stubbed PaymentRequest.
const spcContext = await browser.newContext();
const spcPage = await spcContext.newPage();
const spcErrors = [];
spcPage.on('pageerror', (error) => spcErrors.push(error.message));
const spcCdp = await spcContext.newCDPSession(spcPage);
await spcCdp.send('WebAuthn.enable');
await spcCdp.send('WebAuthn.addVirtualAuthenticator', { options: AUTHENTICATOR });
// A browser that advertises SPC but cannot complete it — the case that must
// degrade to plain WebAuthn rather than stranding the customer.
await spcPage.addInitScript(() => {
  window.PaymentRequest = class {
    constructor(methods, details) {
      this.methods = methods;
      this.details = details;
    }
    async canMakePayment() {
      return true;
    }
    async show() {
      throw new DOMException('no matching credential', 'NotAllowedError');
    }
  };
});
await spcPage.goto(BASE, { waitUntil: 'networkidle' });
check('SPC is advertised in the environment badges', /Secure Payment Confirmation: yes/.test(await spcPage.locator('#env-badges').innerText()));

await spcPage.click('#btn-register');
await spcPage.waitForSelector('.cred h3', { timeout: 20000 });
check('the credential records that the payment extension was requested', /SPC-eligible/.test(await spcPage.locator('#cred-list').innerText()));

await spcPage.click('#scenarios .scenario[data-scenario="payment"]');
await spcPage.click('#btn-assess');
await spcPage.waitForSelector('#btn-proceed-sca');
await spcPage.click('#btn-proceed-sca');
await spcPage.waitForSelector('#btn-auth-plain');
check('the SPC step-up is offered when the browser advertises it', (await spcPage.locator('#btn-auth-spc').count()) === 1);
check('no SPC step-up is offered for a beneficiary change', await (async () => {
  await spcPage.click('#scenarios .scenario[data-scenario="beneficiary"]');
  await spcPage.click('#form-beneficiary button[type="submit"]');
  await spcPage.waitForSelector('#btn-proceed-sca');
  await spcPage.click('#btn-proceed-sca');
  await spcPage.waitForSelector('#btn-auth-plain');
  const none = (await spcPage.locator('#btn-auth-spc').count()) === 0;
  await spcPage.click('#scenarios .scenario[data-scenario="payment"]');
  await spcPage.click('#btn-assess');
  await spcPage.waitForSelector('#btn-proceed-sca');
  await spcPage.click('#btn-proceed-sca');
  await spcPage.waitForSelector('#btn-auth-spc');
  return none;
})());

await spcPage.click('#btn-auth-spc');
await spcPage.waitForFunction(() => /executed|Merchant XYZ/.test(document.querySelector('#verify-body')?.textContent ?? ''), null, { timeout: 20000 });
check('a failed SPC attempt falls back to plain WebAuthn', /falling back to plain WebAuthn/.test(await spcPage.locator('#audit-log').innerText()));
const spcRows = await cells(spcPage, '#verify-body .checklist li');
check('the fallback still produces a valid authorisation', spcRows.every((c) => c.state !== 'fail'), JSON.stringify(spcRows.filter((c) => c.state === 'fail')));
check('no page errors on the SPC path', spcErrors.length === 0, spcErrors.join(' | '));
await spcContext.close();

// --- a passkey that is not a local platform authenticator ------------------
// The portal is opened on a desktop while the passkey lives elsewhere — on a
// phone over hybrid transport, or on a security key. Chromium's virtual
// authenticator cannot emulate hybrid ("cable" is not a valid CDP transport),
// so this covers the next closest thing: a credential whose transport is not
// "internal", proving nothing in the flow assumes a platform authenticator.
for (const transport of ['ble', 'usb']) {
  const roamingContext = await browser.newContext();
  const roaming = await roamingContext.newPage();
  const roamingErrors = [];
  roaming.on('pageerror', (error) => roamingErrors.push(error.message));
  const roamingCdp = await roamingContext.newCDPSession(roaming);
  await roamingCdp.send('WebAuthn.enable');
  await roamingCdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { ...AUTHENTICATOR, transport },
  });

  await roaming.goto(BASE, { waitUntil: 'networkidle' });
  await roaming.click('#btn-register');
  await roaming.waitForSelector('.cred h3', { timeout: 20000 });
  check(`a ${transport} credential enrols`, new RegExp(transport).test(await roaming.locator('#cred-list').innerText()));

  await roaming.click('#scenarios .scenario[data-scenario="payment"]');
  await roaming.click('#btn-assess');
  await roaming.waitForSelector('#btn-proceed-sca');
  await roaming.click('#btn-proceed-sca');
  await roaming.waitForSelector('#btn-auth-plain');
  await roaming.click('#btn-auth-plain');
  await roaming.waitForFunction(
    () => /credited to/.test(document.querySelector('#verify-body')?.textContent ?? ''),
    null,
    { timeout: 20000 },
  );
  const rows = await cells(roaming, '#verify-body .checklist li');
  check(`a ${transport} credential authorises a payment`, rows.length > 0 && rows.every((c) => c.state !== 'fail'), JSON.stringify(rows.filter((c) => c.state === 'fail')));
  check(`no page errors on the ${transport} path`, roamingErrors.length === 0, roamingErrors.join(' | '));
  await roamingContext.close();
}

// --- state written by an earlier version of the demo -----------------------
// The three-scenario rewrite changed the ledger shape. State persists in
// localStorage across deploys, so an unmigrated entry must not break startup.
const legacyContext = await browser.newContext();
const legacy = await legacyContext.newPage();
const legacyErrors = [];
legacy.on('pageerror', (error) => legacyErrors.push(error.message));
await legacy.addInitScript(() => {
  localStorage.setItem(
    'sca-rts-demo/bank-state/v1',
    JSON.stringify({
      user: { id: 'AAAAAAAAAAAAAAAAAAAAAA', name: 'legacy@example.eu', displayName: 'Legacy User' },
      credentials: {},
      lowValueCounters: { amountEur: 24, count: 2 },
      seq: 2,
      ledger: [
        {
          sequence: 2,
          executedAt: '2026-01-01T00:00:00Z',
          authenticated: true,
          exemption: null,
          credentialId: 'legacy-credential',
          signCount: 3,
          transaction: {
            schema: 'sca-rts-demo/transaction/1',
            txnId: 'TX-legacy',
            amount: '48.00',
            currency: 'EUR',
            payee: { name: 'Legacy Payee Ltd', iban: 'IE29AIBK93115212345678' },
            reference: 'OLD-1',
          },
        },
      ],
    }),
  );
});
await legacy.goto(BASE, { waitUntil: 'networkidle' });
check('the demo starts with state from an earlier version', (await legacy.locator('#scenarios').count()) === 1);
check('no startup error banner is shown', !/failed to start/i.test(await legacy.locator('body').innerText()));
check('a legacy ledger entry is migrated and rendered', /Legacy Payee Ltd/.test(await legacy.locator('#ledger').innerText()), await legacy.locator('#ledger').innerText());
check('legacy Art. 16 counters survive the migration', /€24\.00 of €100/.test(await legacy.locator('#counters').innerText()));
check('the migrated page is usable', await legacy.locator('#form-login').isVisible());
check('no page errors on the migrated state', legacyErrors.length === 0, legacyErrors.join(' | '));
await legacyContext.close();

check('no uncaught page errors', pageErrors.length === 0, pageErrors.join(' | '));

await browser.close();
started.server?.close();

console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
