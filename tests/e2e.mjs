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

check('no uncaught page errors', pageErrors.length === 0, pageErrors.join(' | '));

await browser.close();
started.server?.close();

console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
