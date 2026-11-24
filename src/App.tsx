import { useState } from 'react';
import {
  runCheck,
  SAMPLE_SAFE_URL,
  SAMPLE_SUSPICIOUS_URL,
  type CheckResult,
} from './lib/check';
import './App.css';

const VERDICT_LABEL: Record<CheckResult['verdict'], string> = {
  safe: 'Safe',
  caution: 'Caution',
  unsafe: 'Unsafe',
};

const VERDICT_BLURB: Record<CheckResult['verdict'], string> = {
  safe: 'Nothing in the checks raised a flag. Still, only pay if you trust the seller.',
  caution:
    'Something looks off. Read the reasons below before you pay anything.',
  unsafe:
    'Do not pay through this link. One or more checks point at a scam pattern.',
};

function App() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState<CheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  async function onCheck(value?: string) {
    const target = (value ?? input).trim();
    setError(null);
    setResult(null);
    setChecking(true);
    try {
      const out = await runCheck(target);
      if ('error' in out) {
        setError(out.error);
      } else {
        setResult(out);
      }
    } finally {
      setChecking(false);
    }
  }

  return (
    <main className="page">
      <header className="hero">
        <h1>PayShield Check</h1>
        <p className="tagline">
          Check a payment link before you pay it. Rule-based checks only — no
          AI verdict, every reason traces to a shown fact.
        </p>
      </header>

      <section className="checker" aria-label="Check a payment link">
        <label htmlFor="link-input">Payment or checkout link</label>
        <div className="row">
          <input
            id="link-input"
            data-testid="link-input"
            type="text"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            placeholder="https://example.com/pay?order=123"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') void onCheck();
            }}
            disabled={checking}
          />
          <button
            id="check-button"
            data-testid="check-button"
            type="button"
            onClick={() => void onCheck()}
            disabled={checking}
          >
            {checking ? 'Checking…' : 'Check link'}
          </button>
        </div>
        <div className="samples">
          <span>Try one:</span>
          <button
            type="button"
            onClick={() => {
              setInput(SAMPLE_SAFE_URL);
              void onCheck(SAMPLE_SAFE_URL);
            }}
            disabled={checking}
          >
            a safe link
          </button>
          <button
            type="button"
            onClick={() => {
              setInput(SAMPLE_SUSPICIOUS_URL);
              void onCheck(SAMPLE_SUSPICIOUS_URL);
            }}
            disabled={checking}
          >
            a suspicious link
          </button>
        </div>
      </section>

      {error && (
        <section className="error" role="alert" data-testid="error-message">
          {error}
        </section>
      )}

      {result && (
        <section
          className={`verdict verdict-${result.verdict}`}
          data-testid="verdict"
          aria-live="polite"
        >
          <div className="verdict-head">
            <span className="verdict-badge">
              {VERDICT_LABEL[result.verdict]}
            </span>
            <span className="verdict-score">score {result.score}</span>
          </div>
          <p className="verdict-blurb">{VERDICT_BLURB[result.verdict]}</p>

          <h2>Why</h2>
          <ul className="reasons" data-testid="reasons">
            {result.reasons.map((r, i) => (
              <li key={i} className={`reason reason-${r.severity}`}>
                <span className="reason-mark" aria-hidden="true">
                  {r.severity === 'good' ? '+' : r.severity === 'info' ? 'i' : '!'}
                </span>
                {r.text}
                <span className="reason-weight">
                  {r.weight > 0 ? `+${r.weight}` : r.weight}
                </span>
              </li>
            ))}
          </ul>

          <h2>Facts</h2>
          <dl className="facts">
            {result.facts.map((f, i) => (
              <div key={i} className="fact">
                <dt>{f.label}</dt>
                <dd>{f.value}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      <footer className="foot">
        <p>
          Checks: HTTPS, domain age (public RDAP), redirect chain, lookalike
          and lure-word heuristics, and — when the link carries a BNB contract
          address — an on-chain read plus Sourcify verification status. A
          “Safe” result is not a guarantee. Decide for yourself.
        </p>
        <p>
          Built for the Kane CLI Hackathon. Source:{' '}
          <a href="https://github.com/charry99/payshield-check">
            github.com/charry99/payshield-check
          </a>
        </p>
      </footer>
    </main>
  );
}

export default App;
