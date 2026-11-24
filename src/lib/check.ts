// PayShield Check — deterministic, rule-based payment-link safety checks.
// No AI verdict: every reason traces to a shown fact. Pure functions are
// unit-tested in check.test.ts; network checks fail soft (fact, no penalty).

export type Verdict = 'safe' | 'caution' | 'unsafe';

export interface Reason {
  severity: 'critical' | 'warn' | 'good' | 'info';
  text: string;
  weight: number;
}

export interface Fact {
  label: string;
  value: string;
}

export interface CheckResult {
  input: string;
  url: string;
  host: string;
  verdict: Verdict;
  score: number;
  reasons: Reason[];
  facts: Fact[];
}

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'click', 'buzz', 'info', 'online', 'site', 'fun', 'live',
  'loan', 'work', 'tokyo', 'cc', 'su', 'cam', 'zip', 'mov',
]);

const BRANDS = [
  'binance', 'pancakeswap', 'uniswap', 'metamask', 'coinbase', 'opensea',
  'trustwallet', 'paypal', 'ledger', 'trezor', 'kraken', 'bybit', 'okx',
  'phantom', 'solana', 'ethereum', 'tether', 'usdt', 'bnb', 'blockchain',
  'coinmarketcap', 'coingecko',
];

// Display names for brands, so reasons read naturally ("PancakeSwap",
// not "pancakeswap").
const BRAND_DISPLAY: Record<string, string> = {
  binance: 'Binance',
  pancakeswap: 'PancakeSwap',
  uniswap: 'Uniswap',
  metamask: 'MetaMask',
  coinbase: 'Coinbase',
  opensea: 'OpenSea',
  trustwallet: 'Trust Wallet',
  paypal: 'PayPal',
  ledger: 'Ledger',
  trezor: 'Trezor',
  kraken: 'Kraken',
  bybit: 'Bybit',
  okx: 'OKX',
  phantom: 'Phantom',
  solana: 'Solana',
  ethereum: 'Ethereum',
  tether: 'Tether',
  usdt: 'USDT',
  bnb: 'BNB',
  blockchain: 'Blockchain',
  coinmarketcap: 'CoinMarketCap',
  coingecko: 'CoinGecko',
};

// Short brands are only matched exactly (as a subdomain of another domain);
// matching them as substrings would flag legit names like bnbchain.org.
const SHORT_BRANDS = new Set(['bnb', 'okx', 'usdt']);

const SUSPICIOUS_KEYWORDS = [
  'airdrop', 'giveaway', 'double-your', 'claim-now', 'verify-wallet',
  'connect-wallet', 'seed-phrase', 'private-key', 'mnemonic',
];

const BNB_ADDRESS_RE = /0x[0-9a-fA-F]{40}/g;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

export const SAMPLE_SAFE_URL = 'https://pancakeswap.finance/';
export const SAMPLE_SUSPICIOUS_URL = 'https://pancakeswap-airdrop-claim.xyz/';

export function isIpHost(host: string): boolean {
  return host === 'localhost' || IPV4_RE.test(host) || host.includes(':');
}

export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
    prev = cur;
  }
  return prev[n];
}

/** Brand-impersonation / typosquat reasons for a hostname. */
export function typosquatReasons(host: string): Reason[] {
  const reasons: Reason[] = [];
  const labels = host.toLowerCase().split('.');
  // Index of the first label of the registrable domain (naive: last two labels).
  const registrableStart = Math.max(0, labels.length - 2);

  for (let i = 0; i < labels.length; i++) {
    const label = labels[i];
    // The TLD itself is never a lookalike ('finance' is one letter from
    // 'binance' — flagging it would mark pancakeswap.finance as a scam).
    if (i === labels.length - 1) continue;
    if (label.startsWith('xn--')) {
      reasons.push({
        severity: 'critical',
        text: 'Uses punycode (xn--) — a classic way to fake a familiar domain name',
        weight: -40,
      });
      continue;
    }
    for (const brand of BRANDS) {
      if (label === brand) {
        // A brand name as a subdomain of a DIFFERENT domain is impersonation.
        // As the registrable domain itself (binance.com) it is the brand.
        if (i < registrableStart) {
          reasons.push({
            severity: 'critical',
            text: `Uses "${BRAND_DISPLAY[brand] ?? brand}" as a subdomain of a different domain — likely impersonation`,
            weight: -40,
          });
        }
        break;
      }
      if (!SHORT_BRANDS.has(brand) && label.includes(brand)) {
        reasons.push({
          severity: 'critical',
          text: `The name "${label}" contains the brand "${BRAND_DISPLAY[brand] ?? brand}" — likely impersonation`,
          weight: -40,
        });
        break;
      }
      if (
        label.length >= 5 &&
        brand.length >= 4 &&
        levenshtein(label, brand) <= 2
      ) {
        reasons.push({
          severity: 'critical',
          text: `The name "${label}" is one or two letters away from "${BRAND_DISPLAY[brand] ?? brand}" — likely a lookalike`,
          weight: -40,
        });
        break;
      }
    }
  }
  return reasons;
}

/** Static (no-network) reasons for a parsed URL. */
export function analyzeStatic(url: URL): Reason[] {
  const reasons: Reason[] = [];
  const host = url.hostname.toLowerCase();

  if (url.protocol === 'https:') {
    reasons.push({ severity: 'good', text: 'Site uses HTTPS', weight: 5 });
  } else if (url.protocol === 'http:') {
    reasons.push({
      severity: 'warn',
      text: 'Site does not use HTTPS — payment details could be intercepted',
      weight: -25,
    });
  } else {
    reasons.push({
      severity: 'critical',
      text: `Unusual protocol "${url.protocol}" for a payment page`,
      weight: -40,
    });
  }

  if (isIpHost(host)) {
    reasons.push({
      severity: 'critical',
      text: 'Address points at an IP address or local host, not a named domain',
      weight: -40,
    });
  }

  const tld = host.split('.').pop() ?? '';
  if (SUSPICIOUS_TLDS.has(tld)) {
    reasons.push({
      severity: 'warn',
      text: `Uses the .${tld} ending, which is common in scam pages`,
      weight: -10,
    });
  }

  reasons.push(...typosquatReasons(host));

  const haystack = `${host}${url.pathname}${url.search}`.toLowerCase();
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (haystack.includes(kw)) {
      reasons.push({
        severity: 'warn',
        text: `Contains the word "${kw}" — a common lure in scam pages`,
        weight: -15,
      });
    }
  }

  const labels = host.split('.');
  if (labels.length > 4) {
    reasons.push({
      severity: 'warn',
      text: `Unusually deep subdomain chain (${labels.length - 2} subdomains)`,
      weight: -10,
    });
  }

  return reasons;
}

export function extractBnbAddresses(text: string): string[] {
  return [...new Set(text.match(BNB_ADDRESS_RE) ?? [])];
}

export function ageReason(days: number, date: string): Reason {
  if (days < 30) {
    return {
      severity: 'warn',
      text: `Domain registered ${days} day${days === 1 ? '' : 's'} ago — very new`,
      weight: -25,
    };
  }
  if (days < 90) {
    return {
      severity: 'warn',
      text: `Domain registered ${days} days ago — still young`,
      weight: -15,
    };
  }
  if (days < 365) {
    return {
      severity: 'info',
      text: `Domain registered ${days} days ago (${date})`,
      weight: 0,
    };
  }
  return {
    severity: 'good',
    text: `Domain registered over a year ago (${date})`,
    weight: 10,
  };
}

export function scoreVerdict(reasons: Reason[]): { verdict: Verdict; score: number } {
  const score = reasons.reduce((sum, r) => sum + r.weight, 0);
  if (reasons.some((r) => r.severity === 'critical')) {
    return { verdict: 'unsafe', score };
  }
  if (score <= -30) return { verdict: 'unsafe', score };
  if (score < 0) return { verdict: 'caution', score };
  return { verdict: 'safe', score };
}

export function normalizeInput(
  input: string,
): { url: URL } | { error: string } {
  const trimmed = input.trim();
  if (!trimmed) return { error: 'Paste a payment or checkout link first.' };
  if (/\s/.test(trimmed)) {
    return { error: 'That does not look like a link — it contains spaces.' };
  }
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  try {
    const url = new URL(withScheme);
    if (!url.hostname) return { error: 'That link has no domain name.' };
    // The URL parser is lenient — reject hostnames with characters that can
    // never appear in a real domain (e.g. '!' from a mistyped scheme).
    const host = url.hostname;
    const isIpv6 = host.includes(':');
    if (
      !isIpv6 &&
      !/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(host)
    ) {
      return { error: 'That does not look like a link. Check it and try again.' };
    }
    return { url };
  } catch {
    return { error: 'That does not look like a link. Check it and try again.' };
  }
}

function timeoutSignal(ms: number): { signal: AbortSignal; cancel: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}

interface DomainAge {
  days: number;
  date: string;
}

async function fetchDomainAge(host: string): Promise<DomainAge | { error: string }> {
  const { signal, cancel } = timeoutSignal(8000);
  try {
    const res = await fetch(`https://rdap.org/domain/${host}`, {
      signal,
      headers: { accept: 'application/json' },
    });
    if (res.status === 404) {
      return { error: 'no-record' };
    }
    if (!res.ok) return { error: 'unreachable' };
    const data = (await res.json()) as {
      events?: { eventAction?: string; eventDate?: string }[];
    };
    const reg = data.events?.find(
      (e) => e.eventAction === 'registration' && e.eventDate,
    );
    if (!reg?.eventDate) return { error: 'unreachable' };
    const date = reg.eventDate.slice(0, 10);
    const days = Math.max(
      0,
      Math.floor((Date.now() - new Date(reg.eventDate).getTime()) / 86_400_000),
    );
    return { days, date };
  } catch {
    return { error: 'unreachable' };
  } finally {
    cancel();
  }
}

async function checkRedirects(
  url: URL,
): Promise<{ finalUrl: string; redirected: boolean; status: number } | { error: string }> {
  const { signal, cancel } = timeoutSignal(8000);
  try {
    const res = await fetch(url.toString(), { signal });
    return { finalUrl: res.url, redirected: res.redirected, status: res.status };
  } catch {
    return { error: 'unreachable' };
  } finally {
    cancel();
  }
}

async function rpcCall(method: string, params: unknown[]): Promise<unknown> {
  const { signal, cancel } = timeoutSignal(10000);
  try {
    const res = await fetch('https://bsc-dataseed.bnbchain.org', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal,
    });
    if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
    const data = (await res.json()) as { result?: unknown; error?: unknown };
    if (data.error) throw new Error('RPC error');
    return data.result;
  } finally {
    cancel();
  }
}

async function sourcifyMatch(
  address: string,
): Promise<'exact' | 'partial' | 'none' | 'unknown'> {
  const { signal, cancel } = timeoutSignal(8000);
  try {
    const res = await fetch(
      `https://sourcify.dev/server/v2/contracts?chain=56&addresses=${address}`,
      { signal },
    );
    if (!res.ok) return 'unknown';
    const data = (await res.json()) as unknown;
    const first = Array.isArray(data) ? data[0] : null;
    const match = (first as { match?: unknown } | null)?.match;
    if (match === 'exact') return 'exact';
    if (match === 'partial') return 'partial';
    if (match === null || match === undefined) return 'none';
    return 'unknown';
  } catch {
    return 'unknown';
  } finally {
    cancel();
  }
}

async function checkBnbContract(
  address: string,
): Promise<{ reasons: Reason[]; facts: Fact[] }> {
  const reasons: Reason[] = [];
  const facts: Fact[] = [];
  try {
    const code = (await rpcCall('eth_getCode', [address, 'latest'])) as string;
    if (code === '0x' || code === '0X') {
      facts.push({
        label: 'BNB address',
        value: `${address} is a wallet address, not a contract`,
      });
      return { reasons, facts };
    }
    facts.push({ label: 'BNB address', value: `${address} is a contract on BNB Chain` });
    const match = await sourcifyMatch(address);
    if (match === 'exact') {
      reasons.push({
        severity: 'good',
        text: 'Contract source is verified on Sourcify (exact match)',
        weight: 5,
      });
    } else if (match === 'partial') {
      reasons.push({
        severity: 'info',
        text: 'Contract source is only partially verified on Sourcify',
        weight: 0,
      });
    } else if (match === 'none') {
      reasons.push({
        severity: 'warn',
        text: 'Contract exists on BNB Chain but its source is not verified',
        weight: -15,
      });
    } else {
      facts.push({
        label: 'Contract verification',
        value: 'Could not be checked right now',
      });
    }
  } catch {
    facts.push({
      label: 'BNB address',
      value: 'On-chain read failed — the public RPC did not answer',
    });
  }
  return { reasons, facts };
}

/** Full check: static rules plus live RDAP, redirect and (if present) contract reads. */
export async function runCheck(input: string): Promise<CheckResult | { error: string }> {
  const normalized = normalizeInput(input);
  if ('error' in normalized) return normalized;
  const { url } = normalized;
  const host = url.hostname.toLowerCase();

  const reasons: Reason[] = analyzeStatic(url);
  const facts: Fact[] = [
    { label: 'Protocol', value: url.protocol.replace(':', '').toUpperCase() },
    { label: 'Host', value: host },
  ];

  const addresses = extractBnbAddresses(input);

  const [age, redirect, contract] = await Promise.all([
    fetchDomainAge(host),
    checkRedirects(url),
    addresses.length > 0
      ? checkBnbContract(addresses[0])
      : Promise.resolve({ reasons: [] as Reason[], facts: [] as Fact[] }),
  ]);

  if ('days' in age) {
    reasons.push(ageReason(age.days, age.date));
    facts.push({ label: 'Domain registered', value: age.date });
  } else if (age.error === 'no-record') {
    reasons.push({
      severity: 'warn',
      text: 'No public registration record for this domain',
      weight: -15,
    });
  } else {
    facts.push({ label: 'Domain age', value: 'Could not be checked (RDAP unreachable)' });
  }

  if (!('error' in redirect)) {
    facts.push({ label: 'Final address', value: redirect.finalUrl });
    facts.push({ label: 'HTTP status', value: String(redirect.status) });
    if (redirect.redirected) {
      let finalHost = '';
      try {
        finalHost = new URL(redirect.finalUrl).hostname.toLowerCase();
      } catch {
        finalHost = '';
      }
      if (finalHost && finalHost !== host) {
        // A redirect is only a flag when the destination itself looks like
        // an impersonation (rebrands and shorteners redirect to clean
        // domains all the time — e.g. pancakeswap.finance → pancake.xyz).
        const destinationLooksFake = typosquatReasons(finalHost).some(
          (r) => r.severity === 'critical',
        );
        if (destinationLooksFake) {
          reasons.push({
            severity: 'warn',
            text: `Redirects to a different host (${finalHost}) that looks like an impersonation`,
            weight: -15,
          });
        } else {
          reasons.push({
            severity: 'info',
            text: `Redirects to ${finalHost}`,
            weight: 0,
          });
        }
      } else {
        reasons.push({
          severity: 'info',
          text: 'Redirects within the same site',
          weight: 0,
        });
      }
    }
  } else {
    facts.push({
      label: 'Page fetch',
      value: 'Could not be fetched directly from this browser',
    });
  }

  reasons.push(...contract.reasons);
  facts.push(...contract.facts);

  const { verdict, score } = scoreVerdict(reasons);
  return { input: input.trim(), url: url.toString(), host, verdict, score, reasons, facts };
}
