/**
 * SCA decision engine — PSD2 (Directive (EU) 2015/2366) Article 97 and
 * Commission Delegated Regulation (EU) 2018/389 (the RTS on strong customer
 * authentication), applied to the three things a first-party payments portal
 * actually asks a customer to authorise:
 *
 *   1. signing in                 — Art. 97(1)(a), exemptible under RTS Art. 10
 *   2. adding a beneficiary       — Art. 97(1)(c) and RTS Art. 13, not exemptible
 *   3. initiating a credit transfer — Art. 97(1)(b), exemptions in RTS Art. 10–18
 *
 * Every engine returns the same shape so the UI can render one decision panel:
 * a legal `basis` for SCA being in scope at all, the `candidates` considered
 * (including the ones that miss, which is usually the interesting part), and
 * whether dynamic linking applies to what follows.
 */

const EUR_RATES = { EUR: 1, GBP: 1.17, USD: 0.92, SEK: 0.087, PLN: 0.23, DKK: 0.134 };

export const THRESHOLDS = {
  lowValueSingle: 30,
  lowValueCumulative: 100,
  lowValueCount: 5,
  traBands: [
    { limit: 100, fraudRate: 0.13 },
    { limit: 250, fraudRate: 0.06 },
    { limit: 500, fraudRate: 0.01 },
  ],
};

/**
 * RTS Art. 10(2)(b). Originally 90 days; raised to 180 by Commission Delegated
 * Regulation (EU) 2022/2360. Check the consolidated text before relying on it.
 */
export const ACCESS_EXEMPTION_DAYS = 180;

export function toEurEquivalent(amount, currency) {
  const rate = EUR_RATES[currency];
  if (!rate) return { value: Number(amount), indicative: true, unknownRate: true };
  return { value: Number(amount) * rate, indicative: currency !== 'EUR', unknownRate: false };
}

function decide({ basis, candidates, forceSca, dynamicLinking, summaries }) {
  const applicable = candidates.filter((c) => c.applies);
  const scaRequired = applicable.length === 0 || Boolean(forceSca);
  const forced = Boolean(forceSca) && applicable.length > 0;
  const chosenExemption = scaRequired ? null : applicable[0];

  return {
    basis,
    candidates,
    applicable,
    scaRequired,
    forced,
    chosenExemption,
    // RTS Art. 5(1): dynamic linking is mandated when SCA is applied to a
    // remote electronic payment transaction. Other actions may borrow the
    // technique, and this demo does, but the obligation is payment-specific.
    dynamicLinkingRequired: scaRequired && dynamicLinking === 'required',
    dynamicLinking: scaRequired ? dynamicLinking : 'none',
    summary: forced ? summaries.forced : scaRequired ? summaries.required : summaries.exempt(chosenExemption),
  };
}

// ---------------------------------------------------------------- 1. sign in

/**
 * @param {object} context
 * @param {boolean} context.firstAccess   never authenticated on this channel
 * @param {?number} context.lastScaAt     epoch ms of the last SCA, if any
 * @param {string}  context.scope         'account-information' | 'full-portal'
 */
export function assessAccess(context) {
  const now = Date.now();
  const elapsedDays = context.lastScaAt ? (now - context.lastScaAt) / 86_400_000 : Infinity;
  const withinWindow = elapsedDays <= ACCESS_EXEMPTION_DAYS;
  const informationOnly = context.scope === 'account-information';
  const applies = !context.firstAccess && withinWindow && informationOnly;

  const reason = context.firstAccess
    ? 'Art. 10(2)(a): the exemption is never available on first online access.'
    : !withinWindow
      ? context.lastScaAt
        ? `Art. 10(2)(b): ${Math.floor(elapsedDays)} days since the last SCA exceeds the ${ACCESS_EXEMPTION_DAYS}-day window.`
        : `Art. 10(2)(b): no previous SCA on record, so the ${ACCESS_EXEMPTION_DAYS}-day window has not started.`
      : !informationOnly
        ? 'Art. 10(1): the exemption covers viewing balances and the last 90 days of transactions only. This session can initiate payments and change beneficiaries.'
        : `Art. 10: access is limited to balances and recent transactions, and SCA was applied ${Math.floor(elapsedDays)} day(s) ago.`;

  return decide({
    basis: {
      article: 'PSD2 Art. 97(1)(a)',
      text: 'SCA is required where the payer accesses its payment account online.',
    },
    candidates: [
      { article: 'RTS Art. 10', name: 'Account information access', applies, reason },
      {
        article: 'RTS Art. 18',
        name: 'Transaction risk analysis',
        applies: false,
        reason: 'Not applicable: Art. 18 exempts payment transactions, not account access.',
      },
    ],
    forceSca: context.forceSca,
    // A sign-in has no amount and no payee, so there is nothing to bind.
    dynamicLinking: 'none',
    summaries: {
      required: 'SCA required to sign in — no Article 10 exemption applies. Nothing here is dynamically linked: a sign-in has no amount or payee.',
      forced: 'SCA applied by PSP choice — the Article 10 exemption was available but the portal elected to authenticate.',
      exempt: () =>
        `Sign-in exempt under RTS Art. 10 — read-only access within the ${ACCESS_EXEMPTION_DAYS}-day window since the last SCA.`,
    },
  });
}

// ------------------------------------------------------- 2. add beneficiary

/**
 * Adding or amending a payee is the pivot point of most account-takeover fraud:
 * beat this and the attacker never has to beat payment SCA. PSD2 Art. 97(1)(c)
 * catches it, and RTS Art. 13 mandates SCA for trusted-beneficiary list changes
 * specifically. None of the Art. 10–18 exemptions reach a non-payment action.
 */
export function assessBeneficiary(context) {
  return decide({
    basis: context.trusted
      ? {
          article: 'PSD2 Art. 97(1)(c) · RTS Art. 13(1)',
          text: 'SCA is required for any remote action implying a risk of payment fraud, and expressly for creating or amending the list of trusted beneficiaries.',
        }
      : {
          article: 'PSD2 Art. 97(1)(c)',
          text: 'SCA is required where the payer carries out any action through a remote channel which may imply a risk of payment fraud or other abuse.',
        },
    candidates: [
      {
        article: 'RTS Art. 13',
        name: 'Trusted beneficiary',
        applies: false,
        reason: context.trusted
          ? 'Art. 13 is not an exemption here — it is the provision that *requires* SCA to add a payee to the trusted list. The exemption it grants applies later, to payments made to that payee.'
          : 'Art. 13 exempts payments to an established trusted beneficiary. It cannot exempt the act of establishing one.',
      },
      {
        article: 'RTS Art. 16',
        name: 'Low-value payment',
        applies: false,
        reason: 'Not applicable: adding a payee moves no money, so it has no value to compare against the €30 threshold.',
      },
      {
        article: 'RTS Art. 18',
        name: 'Transaction risk analysis',
        applies: false,
        reason: 'Not applicable: Art. 18 exempts payment transactions, not changes to payee records.',
      },
    ],
    forceSca: false,
    // Art. 5 does not reach a non-payment action, but the same commitment
    // technique binds the payee record the customer actually saw.
    dynamicLinking: 'voluntary',
    summaries: {
      required:
        'SCA required — no exemption in Articles 10–18 reaches a non-payment action. Article 5 dynamic linking is not mandated here, but this demo binds the payee name, IBAN and Verification of Payee result into the challenge anyway.',
      forced: '',
      exempt: () => '',
    },
  });
}

// ------------------------------------------------------------- 3. payment

export function assessPayment(txn, context) {
  const eur = toEurEquivalent(txn.amount, txn.currency);
  const amountEur = eur.value;
  const candidates = [];
  const push = (article, name, applies, reason) => candidates.push({ article, name, applies, reason });

  // Art. 11–12 cover proximity and unattended terminals; a portal payment is remote.
  push('RTS Art. 11', 'Contactless at point of sale', false, 'Not applicable: this is a remote electronic payment, not a proximity card payment.');

  push(
    'RTS Art. 13',
    'Trusted beneficiary (whitelist)',
    Boolean(context.trustedBeneficiary),
    context.trustedBeneficiary
      ? `${txn.payee.name} is on the payer's trusted-beneficiary list. Adding it there required SCA in its own right.`
      : 'Payee is not on the payer’s trusted-beneficiary list.',
  );

  const recurringApplies = Boolean(context.recurringMandate) && !context.firstOfSeries;
  push(
    'RTS Art. 14',
    'Recurring transaction (same amount, same payee)',
    recurringApplies,
    context.recurringMandate
      ? context.firstOfSeries
        ? 'First payment of the series: SCA is required when the series is created.'
        : 'Subsequent payment in an established series with an unchanged amount and payee.'
      : 'No recurring mandate is registered for this amount and payee.',
  );

  push(
    'RTS Art. 15',
    'Transfer between the payer’s own accounts',
    Boolean(context.sameOwnerSamePsp),
    context.sameOwnerSamePsp
      ? 'Both accounts are held by the same person at this PSP.'
      : 'Payee account is not held by the payer at this PSP.',
  );

  const counters = context.lowValueCounters ?? { amountEur: 0, count: 0 };
  const underSingle = amountEur <= THRESHOLDS.lowValueSingle;
  const cumulativeAfter = counters.amountEur + amountEur;
  const countAfter = counters.count + 1;
  const lowValueApplies = underSingle && (cumulativeAfter <= THRESHOLDS.lowValueCumulative || countAfter <= THRESHOLDS.lowValueCount);
  push(
    'RTS Art. 16',
    'Low-value remote payment',
    lowValueApplies,
    underSingle
      ? lowValueApplies
        ? `Amount ≤ €30 and, since the last SCA, the running total would be €${cumulativeAfter.toFixed(2)} (limit €100) over ${countAfter} payment(s) (limit 5).`
        : `Amount ≤ €30 but both counters are spent: €${cumulativeAfter.toFixed(2)} of €100 across ${countAfter} of 5 payments since the last SCA.`
      : `Amount €${amountEur.toFixed(2)} exceeds the €30 single-payment limit.`,
  );

  push(
    'RTS Art. 17',
    'Secure corporate payment process',
    Boolean(context.corporateProcess),
    context.corporateProcess
      ? 'Initiated through a dedicated corporate process or protocol available only to legal persons and accepted by the competent authority. Note that a browser portal used by named individuals is a poor fit for Art. 17.'
      : 'Not initiated through a dedicated corporate payment process.',
  );

  const band = THRESHOLDS.traBands.filter((b) => context.fraudRate <= b.fraudRate).sort((a, b) => b.limit - a.limit)[0];
  const traCeiling = band ? band.limit : 0;
  const riskClean = context.riskScore <= context.riskThreshold;
  const traApplies = Boolean(band) && amountEur <= traCeiling && riskClean;
  push(
    'RTS Art. 18',
    'Transaction risk analysis',
    traApplies,
    !band
      ? `Reference fraud rate ${context.fraudRate}% exceeds every RTS band, so no exemption threshold is available.`
      : !riskClean
        ? `Real-time risk score ${context.riskScore}/100 is above the PSP’s acceptance threshold of ${context.riskThreshold}; Art. 18(2)(c) blocks the exemption.`
        : amountEur <= traCeiling
          ? `Amount €${amountEur.toFixed(2)} is within the €${traCeiling} exemption threshold earned by a ${context.fraudRate}% fraud rate, and no abnormal pattern was detected.`
          : `Amount €${amountEur.toFixed(2)} exceeds the €${traCeiling} threshold earned by a ${context.fraudRate}% fraud rate. High-value corporate payments sit above every band, so SCA applies to essentially all of them.`,
  );

  const decision = decide({
    basis: {
      article: 'PSD2 Art. 97(1)(b)',
      text: 'SCA is required where the payer initiates an electronic payment transaction.',
    },
    candidates,
    forceSca: context.forceSca,
    dynamicLinking: 'required',
    summaries: {
      required: 'SCA required — no exemption in Articles 10–18 covers this transaction, so Article 5 dynamic linking applies.',
      forced: 'SCA applied by PSP choice — an exemption was available but the payer’s PSP elected to authenticate (Art. 2 monitoring, Art. 5 dynamic linking applies).',
      exempt: (exemption) =>
        `SCA exempt under ${exemption.article} — ${exemption.name}. The payee’s PSP may still require authentication.`,
    },
  });

  return {
    ...decision,
    amountEur,
    indicativeFx: eur.indicative,
    unknownRate: eur.unknownRate,
    counters: { before: counters, projected: { amountEur: cumulativeAfter, count: countAfter } },
  };
}
