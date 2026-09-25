import React, { useState, useMemo } from 'react';
import { KeyRound, Hash, ShieldCheck, AlertTriangle, Eye, EyeOff, Check, X, ShieldAlert, Cpu } from 'lucide-react';
import { Explainer } from '../Explainer.tsx';

// Hash detection signatures
interface HashMatch {
  name: string;
  category: 'Cryptographic Hash' | 'Key Derivation Function (Password Hash)' | 'Checksum / Non-crypto' | 'Legacy Windows';
  bitLength: number;
  status: 'Broken / Insecure' | 'Secure / Modern' | 'Non-Cryptographic' | 'Vulnerable to GPU Cracking';
  description: string;
}

function identifyHash(raw: string): HashMatch[] {
  const trimmed = raw.trim();
  const hexOnly = /^[0-9a-fA-F]+$/;
  const matches: HashMatch[] = [];

  if (!trimmed) return [];

  // Bcrypt
  if (/^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(trimmed)) {
    matches.push({
      name: 'bcrypt',
      category: 'Key Derivation Function (Password Hash)',
      bitLength: 184,
      status: 'Secure / Modern',
      description: 'Adaptive password-hashing function based on the Blowfish cipher with an adjustable work factor cost.',
    });
  }

  // Argon2
  if (/^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$/.test(trimmed)) {
    matches.push({
      name: 'Argon2 (Argon2id)',
      category: 'Key Derivation Function (Password Hash)',
      bitLength: 256,
      status: 'Secure / Modern',
      description: 'Winner of the Password Hashing Competition (PHC). Designed to be memory-hard to resist ASIC/GPU attacks.',
    });
  }

  // Hex hashes
  if (hexOnly.test(trimmed)) {
    const len = trimmed.length;

    if (len === 8) {
      matches.push({
        name: 'CRC32',
        category: 'Checksum / Non-crypto',
        bitLength: 32,
        status: 'Non-Cryptographic',
        description: 'Cyclic redundancy check used for accidental error detection. Not secure against deliberate tampering.',
      });
    }

    if (len === 32) {
      matches.push({
        name: 'MD5',
        category: 'Cryptographic Hash',
        bitLength: 128,
        status: 'Broken / Insecure',
        description: 'Cryptographically broken due to practical collision attacks. Should never be used for security or passwords.',
      });
      matches.push({
        name: 'NTLM / MD4',
        category: 'Legacy Windows',
        bitLength: 128,
        status: 'Broken / Insecure',
        description: 'Legacy Microsoft authentication hash. Vulnerable to pass-the-hash and rapid offline GPU cracking.',
      });
    }

    if (len === 40) {
      matches.push({
        name: 'SHA-1',
        category: 'Cryptographic Hash',
        bitLength: 160,
        status: 'Broken / Insecure',
        description: 'Broken by Google (SHAttered attack). Collision attacks are practical; deprecated by NIST since 2011.',
      });
    }

    if (len === 64) {
      matches.push({
        name: 'SHA-256 (SHA-2 Family)',
        category: 'Cryptographic Hash',
        bitLength: 256,
        status: 'Secure / Modern',
        description: 'Standard cryptographic digest used in TLS certificates, Bitcoin, and file integrity verification. Fast on GPUs, so passwords must be salted and stretched.',
      });
      matches.push({
        name: 'HMAC-SHA256',
        category: 'Cryptographic Hash',
        bitLength: 256,
        status: 'Secure / Modern',
        description: 'Keyed-hash message authentication code verifying both data integrity and authentication.',
      });
    }

    if (len === 96) {
      matches.push({
        name: 'SHA-384',
        category: 'Cryptographic Hash',
        bitLength: 384,
        status: 'Secure / Modern',
        description: 'Truncated version of SHA-512 commonly specified in high-assurance NSA Suite B cryptography.',
      });
    }

    if (len === 128) {
      matches.push({
        name: 'SHA-512',
        category: 'Cryptographic Hash',
        bitLength: 512,
        status: 'Secure / Modern',
        description: '64-bit word architecture digest with 512-bit output. High collision resistance.',
      });
      matches.push({
        name: 'Whirlpool',
        category: 'Cryptographic Hash',
        bitLength: 512,
        status: 'Secure / Modern',
        description: '512-bit hash based on a modified Advanced Encryption Standard (AES) cipher block.',
      });
    }
  }

  return matches;
}

export const HashPasswordLab: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'entropy' | 'hashIdentifier'>('entropy');

  // Password Entropy state
  const [password, setPassword] = useState('CorrectHorseBatteryStaple!2026');
  const [showPassword, setShowPassword] = useState(true);

  // Hash identifier state
  const [hashInput, setHashInput] = useState('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8');

  // Client-side entropy calculations
  const entropyAnalysis = useMemo(() => {
    if (!password) {
      return {
        entropy: 0,
        poolSize: 0,
        length: 0,
        rating: 'Very Weak',
        hasLower: false,
        hasUpper: false,
        hasDigits: false,
        hasSymbols: false,
        hasRepeatPatterns: false,
        onlineCrackTime: 'Instant',
        gpuRigCrackTime: 'Instant',
      };
    }

    let pool = 0;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigits = /[0-9]/.test(password);
    const hasSymbols = /[^a-zA-Z0-9]/.test(password);

    if (hasLower) pool += 26;
    if (hasUpper) pool += 26;
    if (hasDigits) pool += 10;
    if (hasSymbols) pool += 33;

    // Pattern penalties
    const isSequential = /(?:abc|bcd|cde|def|efg|123|234|345|456|567|678|789|qwe|asd)/i.test(password);
    const isRepeated = /(.)\1{2,}/.test(password);

    const length = password.length;
    // Shannon entropy: H = L * log2(pool)
    let calculatedEntropy = pool > 0 ? length * (Math.log(pool) / Math.log(2)) : 0;

    if (isSequential) calculatedEntropy = Math.max(0, calculatedEntropy - 10);
    if (isRepeated) calculatedEntropy = Math.max(0, calculatedEntropy - 8);

    calculatedEntropy = Math.round(calculatedEntropy * 10) / 10;

    let rating: 'Very Weak' | 'Weak' | 'Moderate' | 'Strong' | 'Very Strong' = 'Very Weak';
    if (calculatedEntropy >= 80) rating = 'Very Strong';
    else if (calculatedEntropy >= 60) rating = 'Strong';
    else if (calculatedEntropy >= 40) rating = 'Moderate';
    else if (calculatedEntropy >= 25) rating = 'Weak';

    // Combinations calculation: pool^length
    // Assume GPU cluster tests 100 Billion hashes/sec (10^11/s)
    // Assume Online throttled server allows 10 attempts/sec
    const totalCombinations = Math.pow(pool, length);

    function formatTime(seconds: number): string {
      if (seconds < 1) return '< 1 second';
      if (seconds < 60) return `${Math.round(seconds)} seconds`;
      if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
      if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
      if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
      if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)} years`;
      if (seconds < 31536000 * 1e6) return `${(seconds / (31536000 * 1e3)).toFixed(1)} thousand years`;
      if (seconds < 31536000 * 1e9) return `${(seconds / (31536000 * 1e6)).toFixed(1)} million years`;
      return `${(seconds / (31536000 * 1e9)).toFixed(1)} billion+ years`;
    }

    const onlineSeconds = totalCombinations / 10;
    const gpuSeconds = totalCombinations / 1e11;

    return {
      entropy: calculatedEntropy,
      poolSize: pool,
      length,
      rating,
      hasLower,
      hasUpper,
      hasDigits,
      hasSymbols,
      hasRepeatPatterns: isSequential || isRepeated,
      onlineCrackTime: formatTime(onlineSeconds),
      gpuRigCrackTime: formatTime(gpuSeconds),
    };
  }, [password]);

  const identifiedHashes = useMemo(() => identifyHash(hashInput), [hashInput]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">Hash & Password Security Lab</h2>
            <Explainer
              term="Entropy & Hashes"
              title="Information Entropy vs Cryptographic Hashes"
              summary="Password strength is governed by Shannon Entropy (unpredictability measured in bits). Hashes are one-way mathematical algorithms transforming arbitrary inputs into fixed-length digests."
              whyItMatters="Passwords with low entropy are easily cracked via dictionary attacks. Using obsolete hash functions like MD5 or unsalted SHA-1 allows attackers to reverse millions of passwords in seconds using precomputed rainbow tables."
              defenseTip="Never store passwords in plain text or with raw SHA-256. Use modern slow key derivation functions like Argon2id or bcrypt with high work factors."
            />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Analyze password entropy, simulate offline brute-force timelines, and identify cryptographic hash formats without sending any secrets over the network.
          </p>
        </div>

        {/* Tab switch */}
        <div className="flex items-center p-1 bg-slate-900 border border-slate-800 rounded-lg">
          <button
            type="button"
            onClick={() => setActiveSubTab('entropy')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
              activeSubTab === 'entropy' ? 'bg-slate-800 text-cyan-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Password Entropy Lab
          </button>
          <button
            type="button"
            onClick={() => setActiveSubTab('hashIdentifier')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
              activeSubTab === 'hashIdentifier' ? 'bg-slate-800 text-cyan-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Hash Format Identifier
          </button>
        </div>
      </div>

      {/* SUBTAB 1: Password Entropy & Strength */}
      {activeSubTab === 'entropy' && (
        <div className="space-y-6">
          {/* Privacy Notice Banner */}
          <div className="p-3 bg-cyan-950/40 border border-cyan-800/60 rounded-xl flex items-center justify-between gap-3 text-xs text-cyan-200">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>
                <strong>Zero-Network Guarantee:</strong> All entropy and brute-force estimations are computed 100% inside your local browser runtime. No passwords or keystrokes are ever transmitted or logged.
              </span>
            </div>
            <Explainer
              term="Zero-Knowledge"
              title="Client-Side Zero-Knowledge Validation"
              summary="Security best practices dictate that sensitive credentials must never be passed to third-party testing services. In-browser math eliminates wire interception risk."
              whyItMatters="Online 'password checkers' that send input over HTTP/HTTPS can be logged in access logs, reverse proxies, or analytics scripts."
            />
          </div>

          {/* Password Input */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
              <span>Test Password String:</span>
              <span className="text-slate-400 font-mono text-[11px]">{entropyAnalysis.length} characters</span>
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Type a password to evaluate..."
                className="w-full px-4 py-3 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono pr-10"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-200"
                aria-label="Toggle password visibility"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Metric Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span>Shannon Entropy</span>
                <Explainer
                  term="Entropy"
                  title="Shannon Entropy in Information Theory"
                  summary="Calculated as H = L × log2(R), where L is password length and R is character pool size (e.g. 95 possible ASCII characters)."
                  whyItMatters="Entropy represents the total search space an attacker must traverse. Every extra bit of entropy doubles the time required to brute-force the secret."
                  defenseTip="Aim for ≥ 64 bits of entropy. A long 4-word passphrase (like CorrectHorseBatteryStaple) provides more entropy than a short complex string like Tr0ub4dor&3."
                />
              </div>
              <div className="text-2xl font-bold font-mono text-cyan-400">{entropyAnalysis.entropy} bits</div>
              <div className="text-xs text-slate-400 mt-1">
                Character Pool Size: <span className="font-mono text-slate-200">{entropyAnalysis.poolSize}</span> chars
              </div>
            </div>

            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span>Estimated Strength</span>
                <Explainer
                  term="Strength Tiers"
                  title="NIST Password Guidelines (SP 800-63B)"
                  summary="Modern NIST standards prioritize password length over artificial symbol complexity rules, emphasizing user-friendly passphrases."
                  whyItMatters="Forcing users to include symbols often leads to predictable replacements (e.g. replacing 'a' with '@'), which attackers program into their cracking dictionaries."
                />
              </div>
              <div
                className={`text-xl font-bold ${
                  entropyAnalysis.rating === 'Very Strong'
                    ? 'text-emerald-400'
                    : entropyAnalysis.rating === 'Strong'
                    ? 'text-cyan-400'
                    : entropyAnalysis.rating === 'Moderate'
                    ? 'text-amber-400'
                    : 'text-rose-400'
                }`}
              >
                {entropyAnalysis.rating}
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                <div
                  className={`h-full transition-all ${
                    entropyAnalysis.rating === 'Very Strong'
                      ? 'bg-emerald-400 w-full'
                      : entropyAnalysis.rating === 'Strong'
                      ? 'bg-cyan-400 w-3/4'
                      : entropyAnalysis.rating === 'Moderate'
                      ? 'bg-amber-400 w-1/2'
                      : 'bg-rose-400 w-1/4'
                  }`}
                />
              </div>
            </div>

            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                <span>Offline GPU Rig Crack Time</span>
                <Explainer
                  term="GPU Cracking"
                  title="Dedicated GPU Cracking Arrays (Hashcat / John the Ripper)"
                  summary="High-end password recovery rigs running 8× RTX 4090 GPUs compute over 100 billion fast NTLM/MD5 hashes per second."
                  whyItMatters="If a database breach leaks unsalted hashes, high-entropy passwords survive while simple passwords fall within seconds."
                />
              </div>
              <div className="text-lg font-bold font-mono text-slate-100 truncate">
                {entropyAnalysis.gpuRigCrackTime}
              </div>
              <div className="text-xs text-slate-400 mt-1">
                Online Throttled: <span className="font-mono text-slate-300">{entropyAnalysis.onlineCrackTime}</span>
              </div>
            </div>
          </div>

          {/* Character Variety Check */}
          <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <span className="text-xs uppercase tracking-wider font-semibold text-slate-300 font-mono">
              Entropy Breakdown Factors
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="flex items-center gap-2">
                {entropyAnalysis.hasLower ? (
                  <Check className="w-4 h-4 text-emerald-400" />
                ) : (
                  <X className="w-4 h-4 text-slate-500" />
                )}
                <span className={entropyAnalysis.hasLower ? 'text-slate-200' : 'text-slate-500'}>
                  Lowercase (a-z)
                </span>
              </div>
              <div className="flex items-center gap-2">
                {entropyAnalysis.hasUpper ? (
                  <Check className="w-4 h-4 text-emerald-400" />
                ) : (
                  <X className="w-4 h-4 text-slate-500" />
                )}
                <span className={entropyAnalysis.hasUpper ? 'text-slate-200' : 'text-slate-500'}>
                  Uppercase (A-Z)
                </span>
              </div>
              <div className="flex items-center gap-2">
                {entropyAnalysis.hasDigits ? (
                  <Check className="w-4 h-4 text-emerald-400" />
                ) : (
                  <X className="w-4 h-4 text-slate-500" />
                )}
                <span className={entropyAnalysis.hasDigits ? 'text-slate-200' : 'text-slate-500'}>
                  Numbers (0-9)
                </span>
              </div>
              <div className="flex items-center gap-2">
                {entropyAnalysis.hasSymbols ? (
                  <Check className="w-4 h-4 text-emerald-400" />
                ) : (
                  <X className="w-4 h-4 text-slate-500" />
                )}
                <span className={entropyAnalysis.hasSymbols ? 'text-slate-200' : 'text-slate-500'}>
                  Symbols (!@#$)
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 2: Hash Format Identifier */}
      {activeSubTab === 'hashIdentifier' && (
        <div className="space-y-6">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300">
                Paste Hash String to Identify Format (No Cracking):
              </label>
              <Explainer
                term="Hash Identification"
                title="Format & Signature Identification vs Cracking"
                summary="Different algorithms generate hashes with distinct character sets, lengths, and prefix signatures (e.g. bcrypt uses '$2b$', MD5 is exactly 32 hex characters)."
                whyItMatters="Forensic analysts must identify which algorithm encrypted or hashed a leaked artifact before choosing defense or migration strategies."
                defenseTip="Never use brute-force cracking tools on production servers. Migrate legacy MD5/SHA1 password columns to Argon2id immediately."
              />
            </div>
            <textarea
              value={hashInput}
              onChange={(e) => setHashInput(e.target.value)}
              rows={3}
              placeholder="Paste hash (e.g. 5e884898da28... or $2a$12$...)"
              className="w-full px-4 py-2.5 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono resize-none"
            />
            <div className="text-xs text-slate-400 flex items-center justify-between font-mono">
              <span>Input length: {hashInput.trim().length} characters</span>
              <div className="flex items-center gap-1.5">
                <span className="text-slate-400 font-sans">Examples:</span>
                <button
                  type="button"
                  onClick={() => setHashInput('5d41402abc4b2a76b9719d911017c592')}
                  className="px-2 py-0.5 bg-slate-900 hover:bg-slate-800 rounded text-slate-300 text-[11px]"
                >
                  MD5
                </button>
                <button
                  type="button"
                  onClick={() => setHashInput('$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW')}
                  className="px-2 py-0.5 bg-slate-900 hover:bg-slate-800 rounded text-slate-300 text-[11px]"
                >
                  bcrypt
                </button>
                <button
                  type="button"
                  onClick={() => setHashInput('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8')}
                  className="px-2 py-0.5 bg-slate-900 hover:bg-slate-800 rounded text-slate-300 text-[11px]"
                >
                  SHA-256
                </button>
              </div>
            </div>
          </div>

          {/* Results */}
          <div className="space-y-4">
            <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-200 font-mono">
              Candidate Algorithm Matches ({identifiedHashes.length})
            </h3>

            {identifiedHashes.length > 0 ? (
              <div className="grid grid-cols-1 gap-3">
                {identifiedHashes.map((match, i) => (
                  <div
                    key={i}
                    className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-2"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-3">
                        <span className="font-mono font-bold text-sm text-cyan-400">{match.name}</span>
                        <span className="text-xs text-slate-400 font-mono">{match.bitLength}-bit</span>
                      </div>
                      <span
                        className={`text-xs font-mono font-semibold px-2 py-0.5 rounded border ${
                          match.status.includes('Secure')
                            ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                            : match.status.includes('Broken')
                            ? 'bg-rose-950/80 text-rose-300 border-rose-800'
                            : 'bg-amber-950/80 text-amber-300 border-amber-800'
                        }`}
                      >
                        {match.status}
                      </span>
                    </div>

                    <p className="text-xs leading-relaxed text-slate-300">{match.description}</p>
                    <div className="text-[11px] text-slate-400 font-mono">Category: {match.category}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-6 text-center bg-slate-900/40 border border-slate-800 rounded-xl text-slate-400 text-xs">
                No standard cryptographic signatures matched the input format. Verify that hex strings contain only 0-9 and a-f characters.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
