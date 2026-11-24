import { describe, expect, it } from 'vitest';
import {
  ageReason,
  analyzeStatic,
  extractBnbAddresses,
  isIpHost,
  levenshtein,
  normalizeInput,
  scoreVerdict,
  typosquatReasons,
} from './check';

describe('normalizeInput', () => {
  it('accepts a full https URL', () => {
    const r = normalizeInput('https://example.com/pay');
    expect('url' in r && r.url.hostname).toBe('example.com');
  });

  it('adds https:// when the scheme is missing', () => {
    const r = normalizeInput('example.com/pay');
    expect('url' in r && r.url.protocol).toBe('https:');
  });

  it('rejects blank input', () => {
    const r = normalizeInput('   ');
    expect('error' in r).toBe(true);
  });

  it('rejects input with spaces', () => {
    const r = normalizeInput('not a url at all');
    expect('error' in r).toBe(true);
  });

  it('rejects garbage that is not a URL', () => {
    const r = normalizeInput('ht!tp://[bad');
    expect('error' in r).toBe(true);
  });
});

describe('isIpHost', () => {
  it('flags IPv4 and localhost', () => {
    expect(isIpHost('1.2.3.4')).toBe(true);
    expect(isIpHost('localhost')).toBe(true);
    expect(isIpHost('::1')).toBe(true);
  });

  it('passes named domains', () => {
    expect(isIpHost('example.com')).toBe(false);
    expect(isIpHost('pay.binance.com')).toBe(false);
  });
});

describe('levenshtein', () => {
  it('measures edit distance', () => {
    expect(levenshtein('binance', 'binance')).toBe(0);
    expect(levenshtein('binance', 'binanc')).toBe(1);
    expect(levenshtein('binance', 'binancex')).toBe(1);
    expect(levenshtein('kitten', 'sitting')).toBe(3);
  });
});

describe('typosquatReasons', () => {
  it('does not flag the real brand domain', () => {
    expect(typosquatReasons('binance.com')).toHaveLength(0);
    expect(typosquatReasons('pancakeswap.finance')).toHaveLength(0);
    expect(typosquatReasons('www.binance.com')).toHaveLength(0);
  });

  it('flags a brand name with extra words attached', () => {
    const r = typosquatReasons('binance-support.com');
    expect(r.some((x) => x.severity === 'critical')).toBe(true);
  });

  it('flags an airdrop-style lookalike', () => {
    const r = typosquatReasons('pancakeswap-airdrop-claim.xyz');
    expect(r.some((x) => x.severity === 'critical')).toBe(true);
  });

  it('flags a brand used as a subdomain of another domain', () => {
    const r = typosquatReasons('binance.com.evil.io');
    expect(r.some((x) => x.severity === 'critical')).toBe(true);
  });

  it('flags a one-letter-off lookalike', () => {
    const r = typosquatReasons('binanc.com');
    expect(r.some((x) => x.severity === 'critical')).toBe(true);
  });

  it('flags punycode', () => {
    const r = typosquatReasons('xn--binance-abc.com');
    expect(r.some((x) => x.text.includes('punycode'))).toBe(true);
  });

  it('does not flag legit BNB-ecosystem names', () => {
    expect(typosquatReasons('bnbchain.org')).toHaveLength(0);
  });
});

describe('analyzeStatic', () => {
  it('rewards HTTPS', () => {
    const r = analyzeStatic(new URL('https://example.com/'));
    expect(r.some((x) => x.text.includes('HTTPS') && x.weight > 0)).toBe(true);
  });

  it('penalises plain HTTP', () => {
    const r = analyzeStatic(new URL('http://example.com/'));
    expect(r.some((x) => x.text.includes('does not use HTTPS'))).toBe(true);
  });

  it('flags suspicious TLDs and lure keywords', () => {
    const r = analyzeStatic(new URL('https://free-airdrop-claim.xyz/'));
    expect(r.some((x) => x.text.includes('.xyz'))).toBe(true);
    expect(r.some((x) => x.text.includes('airdrop'))).toBe(true);
  });

  it('flags deep subdomain chains', () => {
    const r = analyzeStatic(new URL('https://a.b.c.d.example.com/'));
    expect(r.some((x) => x.text.includes('subdomain chain'))).toBe(true);
  });
});

describe('extractBnbAddresses', () => {
  it('finds a 0x address in a URL', () => {
    const addr = '0x4905ce1Ce138001A0abb5f04Aa0Af9C9dD700485';
    expect(extractBnbAddresses(`https://example.com/?c=${addr}`)).toEqual([addr]);
  });

  it('returns empty when there is no address', () => {
    expect(extractBnbAddresses('https://example.com/pay')).toEqual([]);
  });
});

describe('ageReason', () => {
  it('penalises very new domains', () => {
    expect(ageReason(10, '2026-11-14').weight).toBe(-25);
  });

  it('penalises young domains less', () => {
    expect(ageReason(60, '2026-09-25').weight).toBe(-15);
  });

  it('is neutral for middle-aged domains', () => {
    expect(ageReason(200, '2026-05-08').weight).toBe(0);
  });

  it('rewards domains over a year old', () => {
    const r = ageReason(400, '2025-10-20');
    expect(r.weight).toBe(10);
    expect(r.severity).toBe('good');
  });
});

describe('scoreVerdict', () => {
  it('is unsafe on any critical reason', () => {
    const { verdict } = scoreVerdict([
      { severity: 'good', text: 'HTTPS', weight: 5 },
      { severity: 'critical', text: 'impersonation', weight: -40 },
    ]);
    expect(verdict).toBe('unsafe');
  });

  it('is unsafe at -30 or below', () => {
    expect(
      scoreVerdict([{ severity: 'warn', text: 'no https', weight: -25 },
        { severity: 'warn', text: 'young', weight: -15 }]).verdict,
    ).toBe('unsafe');
  });

  it('is caution on a small negative score', () => {
    expect(
      scoreVerdict([{ severity: 'warn', text: 'xyz', weight: -10 }]).verdict,
    ).toBe('caution');
  });

  it('is safe on a zero or positive score', () => {
    expect(scoreVerdict([]).verdict).toBe('safe');
    expect(
      scoreVerdict([{ severity: 'good', text: 'HTTPS', weight: 5 }]).verdict,
    ).toBe('safe');
  });
});
