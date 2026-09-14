/**
 * SCA exemption engine — Commission Delegated Regulation (EU) 2018/389
 * (the RTS on strong customer authentication and common and secure open
 * standards of communication), as applied to a *remote* credit transfer.
 *
 * The engine is deliberately explicit: every candidate exemption is evaluated
 * and reported, including the ones that do not apply, so the demo can show why
 * a transaction ended up requiring SCA.
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

export function toEurEquivalent(amount, currency) {
  const rate = EUR_RATES[currency];
  if (!rate) return { value: Number(amount), indicative: true, unknownRate: true };
  return { value: Number(amount) * rate, indicative: currency !== 'EUR', unknownRate: false };
}

/**
 * @param {object} txn      transaction under assessment
 * @param {object} context  payer-PSP state: counters, lists, risk signals
 */
export function assess(txn, context) {
  const eur = toEurEquivalent(txn.amount, txn.currency);
  const amountEur = eur.value;
  const candidates = [];

  const push = (article, name, applies, reason) => candidates.push({ article, name, applies, reason });

  // Art. 11–12: point-of-sale and unattended-terminal exemptions. A remote
  // credit transfer is initiated over the internet, so these are out of scope.
  push(
    'Art. 11',
    'Contactless at point of sale',
    false,
    'Not applicable: this is a remote electronic payment, not a proximity card payment.',
  );

  // Art. 13 — trusted beneficiaries held on a list maintained by the payer's PSP.
  push(
    'Art. 13',
    'Trusted beneficiary (whitelist)',
    Boolean(context.trustedBeneficiary),
    context.trustedBeneficiary
      ? `${txn.payee.name} is on the payer's trusted-beneficiary list. Adding to that list itself required SCA.`
      : 'Payee is not on the payer’s trusted-beneficiary list.',
  );

  // Art. 14 — recurring transactions of the same amount to the same payee.
  const recurringApplies = Boolean(context.recurringMandate) && !context.firstOfSeries;
  push(
    'Art. 14',
    'Recurring transaction (same amount, same payee)',
    recurringApplies,
    context.recurringMandate
      ? context.firstOfSeries
        ? 'First payment of the series: SCA is required when the series is created.'
        : 'Subsequent payment in an established series with an unchanged amount and payee.'
      : 'No recurring mandate is registered for this amount and payee.',
  );

  // Art. 15 — transfers between accounts held by the same person at the same PSP.
  push(
    'Art. 15',
    'Transfer between the payer’s own accounts',
    Boolean(context.sameOwnerSamePsp),
    context.sameOwnerSamePsp
      ? 'Both accounts are held by the same person at this PSP.'
      : 'Payee account is not held by the payer at this PSP.',
  );

  // Art. 16 — low-value remote payments, subject to running counters.
  const counters = context.lowValueCounters ?? { amountEur: 0, count: 0 };
  const underSingle = amountEur <= THRESHOLDS.lowValueSingle;
  const cumulativeAfter = counters.amountEur + amountEur;
  const countAfter = counters.count + 1;
  const underCumulative = cumulativeAfter <= THRESHOLDS.lowValueCumulative;
  const underCount = countAfter <= THRESHOLDS.lowValueCount;
  const lowValueApplies = underSingle && (underCumulative || underCount);
  push(
    'Art. 16',
    'Low-value remote payment',
    lowValueApplies,
    underSingle
      ? lowValueApplies
        ? `Amount ≤ €30 and, since the last SCA, the running total would be €${cumulativeAfter.toFixed(2)} (limit €100) over ${countAfter} payment(s) (limit 5).`
        : `Amount ≤ €30 but both counters are spent: €${cumulativeAfter.toFixed(2)} of €100 across ${countAfter} of 5 payments since the last SCA.`
      : `Amount €${amountEur.toFixed(2)} exceeds the €30 single-payment limit.`,
  );

  // Art. 17 — dedicated corporate payment processes for legal persons.
  push(
    'Art. 17',
    'Secure corporate payment process',
    Boolean(context.corporateProcess),
    context.corporateProcess
      ? 'Initiated through a dedicated corporate process/protocol available only to legal persons, accepted by the competent authority.'
      : 'Not initiated through a dedicated corporate payment process.',
  );

  // Art. 18 — transaction risk analysis, banded by the PSP's audited fraud rate.
  const band = THRESHOLDS.traBands
    .filter((b) => context.fraudRate <= b.fraudRate)
    .sort((a, b) => b.limit - a.limit)[0];
  const traCeiling = band ? band.limit : 0;
  const riskClean = context.riskScore <= context.riskThreshold;
  const traApplies = Boolean(band) && amountEur <= traCeiling && riskClean;
  push(
    'Art. 18',
    'Transaction risk analysis',
    traApplies,
    !band
      ? `Reference fraud rate ${context.fraudRate}% exceeds every RTS band, so no exemption threshold is available.`
      : !riskClean
        ? `Real-time risk score ${context.riskScore}/100 is above the PSP’s acceptance threshold of ${context.riskThreshold}; Art. 18(2)(c) blocks the exemption.`
        : amountEur <= traCeiling
          ? `Amount €${amountEur.toFixed(2)} is within the €${traCeiling} exemption threshold earned by a ${context.fraudRate}% fraud rate, and no abnormal pattern was detected.`
          : `Amount €${amountEur.toFixed(2)} exceeds the €${traCeiling} threshold earned by a ${context.fraudRate}% fraud rate.`,
  );

  const applicable = candidates.filter((c) => c.applies);
  const scaRequired = applicable.length === 0 || context.forceSca;

  return {
    amountEur,
    indicativeFx: eur.indicative,
    unknownRate: eur.unknownRate,
    candidates,
    applicable,
    scaRequired,
    forced: Boolean(context.forceSca) && applicable.length > 0,
    chosenExemption: scaRequired ? null : applicable[0],
    // Art. 5(1): dynamic linking is mandated whenever SCA is applied to a
    // remote electronic payment transaction.
    dynamicLinkingRequired: scaRequired,
    counters: { before: counters, projected: { amountEur: cumulativeAfter, count: countAfter } },
  };
}

export function summarise(decision) {
  if (decision.scaRequired && decision.forced) {
    return 'SCA applied by PSP choice — an exemption was available but the payer’s PSP elected to authenticate (Art. 2 monitoring, Art. 5 dynamic linking applies).';
  }
  if (decision.scaRequired) {
    return 'SCA required — no exemption in Articles 10–18 covers this transaction, so Article 5 dynamic linking applies.';
  }
  return `SCA exempt under ${decision.chosenExemption.article} — ${decision.chosenExemption.name}. The payee’s PSP may still require authentication.`;
}
