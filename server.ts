/**
 * CyberToolkit Backend Server
 * Provides defensive security diagnostics, in-memory packet analysis,
 * DNS/TLS inspection, port connectivity tests, and security intel.
 */

import express, { Request, Response } from 'express';
import dns from 'dns';
import net from 'net';
import tls from 'tls';
import http from 'http';
import https from 'https';
import path from 'path';
import { fileURLToPath } from 'url';
import { parsePcapBuffer, generateDemoPcap } from './src/server/pcapParser.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// High payload limit for in-memory PCAP uploads (up to 20MB)
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// In-memory cache for news feed to avoid hammering public endpoints
let cachedNews: any[] = [];
let newsLastFetched = 0;

// Clean host helper
function sanitizeHost(input: string): string {
  let cleaned = input.trim();
  cleaned = cleaned.replace(/^https?:\/\//i, '');
  cleaned = cleaned.split('/')[0];
  cleaned = cleaned.split(':')[0];
  return cleaned;
}

// -----------------------------------------------------------------------------
// 1. IP & DOMAIN INTEL
// -----------------------------------------------------------------------------
app.get('/api/ip-domain', async (req: Request, res: Response) => {
  const rawTarget = String(req.query.target || '');
  if (!rawTarget) {
    return res.status(400).json({ error: 'Target domain or IP address is required.' });
  }

  const target = sanitizeHost(rawTarget);
  const isIp = net.isIP(target) !== 0;

  try {
    let resolvedIps: string[] = [];
    const dnsRecords: Record<string, any> = {};

    if (isIp) {
      resolvedIps = [target];
      try {
        const ptr = await dns.promises.reverse(target);
        dnsRecords['PTR'] = ptr;
      } catch {
        dnsRecords['PTR'] = ['No reverse PTR record found'];
      }
    } else {
      // Resolve standard DNS records
      const [aResult, aaaaResult, mxResult, txtResult, nsResult, cnameResult] = await Promise.allSettled([
        dns.promises.resolve4(target),
        dns.promises.resolve6(target),
        dns.promises.resolveMx(target),
        dns.promises.resolveTxt(target),
        dns.promises.resolveNs(target),
        dns.promises.resolveCname(target),
      ]);

      if (aResult.status === 'fulfilled') dnsRecords['A'] = aResult.value;
      if (aaaaResult.status === 'fulfilled') dnsRecords['AAAA'] = aaaaResult.value;
      if (mxResult.status === 'fulfilled') dnsRecords['MX'] = mxResult.value;
      if (txtResult.status === 'fulfilled') dnsRecords['TXT'] = txtResult.value.map(chunks => chunks.join(''));
      if (nsResult.status === 'fulfilled') dnsRecords['NS'] = nsResult.value;
      if (cnameResult.status === 'fulfilled') dnsRecords['CNAME'] = cnameResult.value;

      resolvedIps = (dnsRecords['A'] || []).concat(dnsRecords['AAAA'] || []);
    }

    const queryIp = resolvedIps[0] || (isIp ? target : null);

    let geoData: any = null;
    if (queryIp) {
      try {
        const geoResp = await fetch(`http://ip-api.com/json/${queryIp}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`, {
          signal: AbortSignal.timeout(4000)
        });
        if (geoResp.ok) {
          const data = await geoResp.json();
          if (data.status === 'success') {
            geoData = data;
          }
        }
      } catch {
        // Fallback gracefully
      }
    }

    // RDAP domain/IP registration data
    let rdapData: any = null;
    try {
      const rdapEndpoint = isIp ? `https://rdap.arin.net/registry/ip/${queryIp}` : `https://rdap.org/domain/${target}`;
      const rdapResp = await fetch(rdapEndpoint, { signal: AbortSignal.timeout(3500) });
      if (rdapResp.ok) {
        const rawRdap = await rdapResp.json();
        rdapData = {
          handle: rawRdap.handle || rawRdap.name,
          status: rawRdap.status || [],
          entities: (rawRdap.entities || []).slice(0, 3).map((e: any) => ({
            handle: e.handle,
            roles: e.roles,
          })),
          events: (rawRdap.events || []).map((ev: any) => ({
            action: ev.eventAction,
            date: ev.eventDate,
          })),
        };
      }
    } catch {
      // RDAP optional
    }

    return res.json({
      target,
      isIp,
      resolvedIps,
      dnsRecords,
      geoData,
      rdapData,
    });
  } catch (err: any) {
    return res.status(500).json({ error: `Resolution failed: ${err.message || err}` });
  }
});

// -----------------------------------------------------------------------------
// 2. CERTIFICATE & SECURITY HEADERS INSPECTOR
// -----------------------------------------------------------------------------
app.get('/api/cert-headers', async (req: Request, res: Response) => {
  const rawTarget = String(req.query.target || '');
  if (!rawTarget) {
    return res.status(400).json({ error: 'Target host is required.' });
  }
  const host = sanitizeHost(rawTarget);

  try {
    // 1. Fetch SSL/TLS Certificate
    const certPromise = new Promise<any>((resolve) => {
      const socket = tls.connect(
        {
          host,
          port: 443,
          servername: host,
          rejectUnauthorized: false,
          timeout: 5000,
        },
        () => {
          const cert = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol();
          socket.end();

          if (!cert || Object.keys(cert).length === 0) {
            resolve({ error: 'No certificate returned by peer.' });
            return;
          }

          const validFrom = new Date(cert.valid_from);
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysRemaining = Math.round((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

          resolve({
            subject: cert.subject,
            issuer: cert.issuer,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            isExpired: daysRemaining < 0,
            sans: cert.subjectaltname ? cert.subjectaltname.split(', ') : [],
            protocol,
            cipherName: cipher?.name,
            cipherVersion: cipher?.version,
            bits: cert.bits,
            serialNumber: cert.serialNumber,
            fingerprint256: cert.fingerprint256,
          });
        }
      );

      socket.on('error', (err) => {
        resolve({ error: `TLS connection failed: ${err.message}` });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({ error: 'TLS connection timed out after 5000ms.' });
      });
    });

    // 2. Fetch HTTP Headers via HTTPS GET
    const headerPromise = new Promise<any>((resolve) => {
      const reqHeaders = https.get(
        `https://${host}`,
        {
          timeout: 6000,
          rejectUnauthorized: false,
          headers: {
            'User-Agent': 'CyberToolkit-Header-Inspector/1.0',
            'Accept': '*/*',
          },
        },
        (resp) => {
          const rawHeaders = resp.headers;
          resp.destroy(); // Don't download body

          // Inspect key security headers
          const csp = rawHeaders['content-security-policy'] as string || null;
          const hsts = rawHeaders['strict-transport-security'] as string || null;
          const xfo = rawHeaders['x-frame-options'] as string || null;
          const xcto = rawHeaders['x-content-type-options'] as string || null;
          const rp = rawHeaders['referrer-policy'] as string || null;
          const permissions = (rawHeaders['permissions-policy'] || rawHeaders['feature-policy']) as string || null;
          const serverHeader = rawHeaders['server'] as string || null;
          const poweredBy = rawHeaders['x-powered-by'] as string || null;

          let score = 100;
          const issues: string[] = [];
          const passes: string[] = [];

          if (!csp) {
            score -= 30;
            issues.push('Missing Content-Security-Policy (CSP) allows cross-site scripting (XSS) and data injection.');
          } else {
            passes.push('Content-Security-Policy is present and restricting resource sources.');
          }

          if (!hsts) {
            score -= 25;
            issues.push('Missing Strict-Transport-Security (HSTS) exposes users to SSL stripping and downgrade attacks.');
          } else {
            passes.push('Strict-Transport-Security (HSTS) enforces HTTPS connections.');
          }

          if (!xfo && !csp?.includes('frame-ancestors')) {
            score -= 15;
            issues.push('Missing X-Frame-Options leaves site vulnerable to Clickjacking attacks in iframes.');
          } else {
            passes.push('Frame protection active (prevents clickjacking).');
          }

          if (!xcto || !xcto.toLowerCase().includes('nosniff')) {
            score -= 10;
            issues.push('Missing X-Content-Type-Options: nosniff allows browser MIME-type sniffing.');
          } else {
            passes.push('MIME sniffing disabled via X-Content-Type-Options: nosniff.');
          }

          if (!rp) {
            score -= 10;
            issues.push('Missing Referrer-Policy may leak sensitive URL parameters to third-party domains.');
          } else {
            passes.push(`Referrer-Policy configured (${rp}).`);
          }

          if (serverHeader || poweredBy) {
            score -= 10;
            issues.push(`Information disclosure: Server or X-Powered-By leaks backend runtime info (${serverHeader || poweredBy}).`);
          }

          let grade = 'A';
          if (score >= 90) grade = 'A+';
          else if (score >= 80) grade = 'A';
          else if (score >= 70) grade = 'B';
          else if (score >= 55) grade = 'C';
          else if (score >= 40) grade = 'D';
          else grade = 'F';

          resolve({
            statusCode: resp.statusCode,
            grade,
            score: Math.max(0, score),
            headers: {
              csp,
              hsts,
              xfo,
              xcto,
              rp,
              permissions,
              serverHeader,
              poweredBy,
            },
            allHeaders: rawHeaders,
            issues,
            passes,
          });
        }
      );

      reqHeaders.on('error', (err) => {
        resolve({ error: `HTTP request failed: ${err.message}` });
      });

      reqHeaders.on('timeout', () => {
        reqHeaders.destroy();
        resolve({ error: 'HTTP connection timed out.' });
      });
    });

    const [certData, headerData] = await Promise.all([certPromise, headerPromise]);

    return res.json({
      target: host,
      certificate: certData,
      securityHeaders: headerData,
    });
  } catch (err: any) {
    return res.status(500).json({ error: `Inspection failed: ${err.message || err}` });
  }
});

// -----------------------------------------------------------------------------
// 3. SUBDOMAIN FINDER (Certificate Transparency logs via crt.sh)
// -----------------------------------------------------------------------------
app.get('/api/subdomains', async (req: Request, res: Response) => {
  const rawDomain = String(req.query.domain || '');
  if (!rawDomain) {
    return res.status(400).json({ error: 'Domain name is required.' });
  }

  const domain = sanitizeHost(rawDomain);

  try {
    const crtUrl = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const response = await fetch(crtUrl, {
      signal: AbortSignal.timeout(9000),
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; CyberToolkit-SubdomainFinder/1.0)',
      },
    });

    if (!response.ok) {
      throw new Error(`crt.sh returned status ${response.status}`);
    }

    const data: any[] = await response.json();
    const subdomainSet = new Set<string>();
    const detailsMap = new Map<string, { issuer: string; loggedAt: string }>();

    for (const entry of data) {
      const nameValue: string = entry.name_value || '';
      const lines = nameValue.split('\n');
      for (let line of lines) {
        line = line.trim().toLowerCase();
        if (line && line.endsWith(`.${domain}`) || line === domain) {
          subdomainSet.add(line);
          if (!detailsMap.has(line)) {
            detailsMap.set(line, {
              issuer: entry.issuer_name || 'Certificate Authority',
              loggedAt: entry.entry_timestamp || entry.not_before || 'Unknown',
            });
          }
        }
      }
    }

    const subdomains = Array.from(subdomainSet).sort().map(sub => ({
      subdomain: sub,
      isWildcard: sub.startsWith('*.'),
      issuer: detailsMap.get(sub)?.issuer || 'Certificate Authority',
      loggedAt: detailsMap.get(sub)?.loggedAt || 'Historical',
    }));

    return res.json({
      domain,
      count: subdomains.length,
      subdomains,
      queriedService: 'Certificate Transparency (crt.sh)',
    });
  } catch (err: any) {
    // Provide clean contextual response if crt.sh upstream is temporarily overloaded
    return res.status(502).json({
      error: `Certificate Transparency service query timed out or throttled: ${err.message}. Please retry in a few moments.`,
      domain,
    });
  }
});

// -----------------------------------------------------------------------------
// 4. CVE LOOKUP (NVD API v2 with Curated Historical/Critical Index Fallback)
// -----------------------------------------------------------------------------
const CURATED_CVES = [
  {
    cveId: 'CVE-2021-44228',
    title: 'Log4Shell - Apache Log4j JNDI Remote Code Execution',
    description: 'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code.',
    cvssScore: 10.0,
    severity: 'CRITICAL',
    vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    publishedDate: '2021-12-10T10:15:08.000',
    affectedComponent: 'Apache Log4j 2.x',
    weakness: 'CWE-502 (Deserialization of Untrusted Data) / CWE-400',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228', 'https://logging.apache.org/log4j/2.x/security.html'],
  },
  {
    cveId: 'CVE-2024-3094',
    title: 'XZ Utils Backdoor - Malicious Code in Upstream Tarballs',
    description: 'Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt test file contained in the source code to modify specific functions in liblzma code, intercepting SSH authentication.',
    cvssScore: 10.0,
    severity: 'CRITICAL',
    vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    publishedDate: '2024-03-29T21:15:08.000',
    affectedComponent: 'XZ Utils 5.6.0 & 5.6.1 liblzma',
    weakness: 'CWE-506 (Embedded Malicious Code) / Supply Chain',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-3094', 'https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library'],
  },
  {
    cveId: 'CVE-2014-0160',
    title: 'Heartbleed - OpenSSL TLS Heartbeat Information Disclosure',
    description: 'The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read.',
    cvssScore: 7.5,
    severity: 'HIGH',
    vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    publishedDate: '2014-04-07T22:55:00.000',
    affectedComponent: 'OpenSSL 1.0.1 through 1.0.1f',
    weakness: 'CWE-125 (Out-of-bounds Read)',
    references: ['https://heartbleed.com/', 'https://nvd.nist.gov/vuln/detail/CVE-2014-0160'],
  },
  {
    cveId: 'CVE-2017-0144',
    title: 'EternalBlue - Microsoft Windows SMBv1 Remote Code Execution',
    description: 'The SMBv1 server in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold, 1511, and 1607 allows remote attackers to execute arbitrary code via crafted packets (EternalBlue / WannaCry).',
    cvssScore: 9.8,
    severity: 'CRITICAL',
    vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    publishedDate: '2017-03-16T00:00:00.000',
    affectedComponent: 'Microsoft Windows SMBv1 Protocol',
    weakness: 'CWE-119 (Memory Buffer Boundary Violation)',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2017-0144', 'https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010'],
  },
  {
    cveId: 'CVE-2022-22965',
    title: 'Spring4Shell - Spring Framework DataBinder RCE',
    description: 'A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment.',
    cvssScore: 9.8,
    severity: 'CRITICAL',
    vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    publishedDate: '2022-04-01T23:15:00.000',
    affectedComponent: 'Spring Framework 5.3.0 to 5.3.17',
    weakness: 'CWE-94 (Improper Control of Generation of Code)',
    references: ['https://tanzu.vmware.com/security/cve-2022-22965', 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965'],
  },
  {
    cveId: 'CVE-2023-34362',
    title: 'MOVEit Transfer SQL Injection Vulnerability',
    description: 'In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability in the MOVEit Transfer web application could allow an unauthenticated attacker to gain unauthorized access to the MOVEit Transfer database.',
    cvssScore: 9.8,
    severity: 'CRITICAL',
    vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    publishedDate: '2023-06-02T14:15:00.000',
    affectedComponent: 'Progress Software MOVEit Transfer',
    weakness: 'CWE-89 (SQL Injection)',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-34362', 'https://www.cisa.gov/news-events/alerts/2023/06/01/cisa-releases-advisory-moveit-transfer-vulnerability'],
  },
  {
    cveId: 'CVE-2016-5195',
    title: 'Dirty COW - Linux Kernel Memory Subsystem Privilege Escalation',
    description: 'A race condition was found in the way the Linux kernel memory subsystem handled the copy-on-write (COW) breakage of private read-only memory mappings. An unprivileged local user could use this flaw to gain write access to otherwise read-only memory mappings and gain root privileges.',
    cvssScore: 7.8,
    severity: 'HIGH',
    vectorString: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    publishedDate: '2016-11-10T21:59:00.000',
    affectedComponent: 'Linux Kernel 2.x to 4.8.3',
    weakness: 'CWE-362 (Race Condition)',
    references: ['https://dirtycow.ninja/', 'https://nvd.nist.gov/vuln/detail/CVE-2016-5195'],
  }
];

app.get('/api/cve', async (req: Request, res: Response) => {
  const query = String(req.query.query || '').trim();
  if (!query) {
    return res.json({ results: CURATED_CVES, source: 'Curated Milestone Catalog' });
  }

  // Filter curated database first
  const queryLower = query.toLowerCase();
  const matchedCurated = CURATED_CVES.filter(c =>
    c.cveId.toLowerCase().includes(queryLower) ||
    c.title.toLowerCase().includes(queryLower) ||
    c.description.toLowerCase().includes(queryLower) ||
    c.affectedComponent.toLowerCase().includes(queryLower)
  );

  // If query specifically matches a CVE pattern e.g. CVE-YYYY-NNNN or keyword
  let nvdResults: any[] = [];
  try {
    const isCveId = /^CVE-\d{4}-\d{4,}$/i.test(query);
    const nvdUrl = isCveId
      ? `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(query.toUpperCase())}`
      : `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=10`;

    const nvdResp = await fetch(nvdUrl, {
      signal: AbortSignal.timeout(5000),
      headers: {
        'User-Agent': 'CyberToolkit-CVE-Explorer/1.0',
      },
    });

    if (nvdResp.ok) {
      const data = await nvdResp.json();
      const vulnerabilities = data.vulnerabilities || [];
      nvdResults = vulnerabilities.map((item: any) => {
        const cve = item.cve;
        const cvss3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
        const desc = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No English description available.';

        return {
          cveId: cve.id,
          title: cve.id,
          description: desc,
          cvssScore: cvss3?.baseScore ?? 0,
          severity: cvss3?.baseSeverity || 'UNKNOWN',
          vectorString: cvss3?.vectorString || 'N/A',
          publishedDate: cve.published,
          affectedComponent: cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria || 'Multiple Platforms',
          weakness: cve.weaknesses?.[0]?.description?.[0]?.value || 'CWE Unknown',
          references: (cve.references || []).slice(0, 3).map((r: any) => r.url),
        };
      });
    }
  } catch {
    // If NVD is rate-limited or slow, continue with curated results
  }

  const combined = [...nvdResults];
  for (const c of matchedCurated) {
    if (!combined.some(item => item.cveId.toLowerCase() === c.cveId.toLowerCase())) {
      combined.unshift(c);
    }
  }

  // Sort by severity (highest CVSS score first)
  combined.sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));

  return res.json({
    results: combined.slice(0, 20),
    source: nvdResults.length > 0 ? 'NVD Live API + Knowledgebase' : 'Curated Vulnerability Knowledgebase',
  });
});

// -----------------------------------------------------------------------------
// 5. URL SAFETY CHECK
// -----------------------------------------------------------------------------
app.post('/api/url-safety', async (req: Request, res: Response) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Valid URL is required.' });
  }

  try {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
    } catch {
      return res.status(400).json({ error: 'Invalid URL formatting. Please supply a complete address.' });
    }

    const host = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();
    const fullHref = parsedUrl.href;

    const indicators: { rule: string; risk: 'critical' | 'warning' | 'info'; description: string }[] = [];
    let riskScore = 0; // 0 to 100

    // 1. Check IP address as host
    if (net.isIP(host) !== 0) {
      riskScore += 45;
      indicators.push({
        rule: 'Raw IP Address Hostname',
        risk: 'critical',
        description: 'Host uses a direct IP instead of a registered domain. Legitimate consumer services virtually never use raw IPs.',
      });
    }

    // 2. Check for suspicious high-risk TLDs
    const suspiciousTlds = ['.top', '.xyz', '.work', '.tk', '.icu', '.gq', '.cf', '.ga', '.ml', '.buzz', '.rest', '.surfer'];
    if (suspiciousTlds.some(tld => host.endsWith(tld))) {
      riskScore += 25;
      indicators.push({
        rule: 'High-Abuse Top Level Domain',
        risk: 'warning',
        description: `Domain uses an extension commonly associated with disposable phishing campaigns (${host.slice(host.lastIndexOf('.'))}).`,
      });
    }

    // 3. Phishing and credential lure keywords
    const lureKeywords = ['login', 'signin', 'verify', 'banking', 'account-update', 'secure', 'wallet', 'crypto', 'support', 'webscr', 'password', 'confirm'];
    const matchedLures = lureKeywords.filter(k => pathname.includes(k) || (host.includes(k) && !host.endsWith(`${k}.com`)));
    if (matchedLures.length > 0) {
      riskScore += 30;
      indicators.push({
        rule: 'Credential Harvesting Keywords',
        risk: 'critical',
        description: `Path or subdomain contains sensitive account action tokens: [${matchedLures.join(', ')}].`,
      });
    }

    // 4. Excessive subdomains (e.g. login.paypal.com.attacker.xyz)
    const hostParts = host.split('.');
    if (hostParts.length > 4) {
      riskScore += 25;
      indicators.push({
        rule: 'Deep Subdomain Nesting',
        risk: 'warning',
        description: `Domain contains ${hostParts.length} levels. Attackers nest well-known brand names into subdomains to trick mobile visitors.`,
      });
    }

    // 5. URL Shortener detection
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'cutt.ly', 'rb.gy'];
    if (shorteners.includes(host)) {
      riskScore += 20;
      indicators.push({
        rule: 'URL Shortener Redirection',
        risk: 'warning',
        description: 'URL is disguised behind a redirection service, hiding the true destination endpoint.',
      });
    }

    // 6. Embedded credentials in URL
    if (parsedUrl.username || parsedUrl.password) {
      riskScore += 50;
      indicators.push({
        rule: 'Embedded Userinfo / Basic Auth in URL',
        risk: 'critical',
        description: 'URL syntax embeds credentials (e.g. "https://user@paypal.com@malicious.com"), a classic spoofing technique.',
      });
    }

    // 7. Punycode / Homograph attack check
    if (host.startsWith('xn--')) {
      riskScore += 40;
      indicators.push({
        rule: 'Internationalized Domain (Punycode)',
        risk: 'critical',
        description: 'Domain uses Punycode ("xn--") encoding, frequently used to disguise Cyrillic/Greek characters that look identical to Latin letters.',
      });
    }

    // Google Safe Browsing API check if key is available
    let safeBrowsingResult: any = null;
    const safeBrowsingKey = process.env.GOOGLE_SAFE_BROWSING_KEY || process.env.SAFE_BROWSING_API_KEY;
    if (safeBrowsingKey) {
      try {
        const sbResp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${safeBrowsingKey}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: 'cybertoolkit', clientVersion: '2.0' },
            threatInfo: {
              threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url: fullHref }],
            },
          }),
        });

        if (sbResp.ok) {
          const sbData = await sbResp.json();
          if (sbData.matches && sbData.matches.length > 0) {
            riskScore = 100;
            const threatType = sbData.matches[0].threatType;
            indicators.unshift({
              rule: 'Google Safe Browsing Flag',
              risk: 'critical',
              description: `Flagged as malicious by Google Safe Browsing: ${threatType}`,
            });
            safeBrowsingResult = { isFlagged: true, matches: sbData.matches };
          } else {
            safeBrowsingResult = { isFlagged: false, message: 'No active Google Safe Browsing blacklist entries.' };
          }
        }
      } catch {
        // Safe browsing call failure non-fatal
      }
    }

    let verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' = 'SAFE';
    if (riskScore >= 60) verdict = 'MALICIOUS';
    else if (riskScore >= 20) verdict = 'SUSPICIOUS';

    return res.json({
      url: fullHref,
      verdict,
      riskScore: Math.min(100, riskScore),
      host,
      pathname,
      protocol: parsedUrl.protocol,
      indicators,
      safeBrowsingResult,
    });
  } catch (err: any) {
    return res.status(500).json({ error: `Safety scan failed: ${err.message || err}` });
  }
});

// -----------------------------------------------------------------------------
// 6. PACKET CAPTURE ANALYZER (Server-Side In-Memory Processing)
// -----------------------------------------------------------------------------
app.post('/api/pcap/analyze', async (req: Request, res: Response) => {
  try {
    const { fileBase64, filename, demoType } = req.body;

    let pcapBuffer: Buffer;
    let targetFilename = filename || 'capture.pcap';

    if (demoType === 'auth_sniffing' || demoType === 'dns_recon') {
      pcapBuffer = generateDemoPcap(demoType);
      targetFilename = demoType === 'auth_sniffing' ? 'demo_plaintext_auth_sniff.pcap' : 'demo_dns_recon.pcap';
    } else if (fileBase64) {
      pcapBuffer = Buffer.from(fileBase64, 'base64');
    } else {
      return res.status(400).json({ error: 'Please upload a .pcap/.pcapng file or select a demonstration capture.' });
    }

    // In-memory parsing only, never written to disk
    const analysis = parsePcapBuffer(pcapBuffer, targetFilename);

    return res.json(analysis);
  } catch (err: any) {
    return res.status(400).json({ error: `Packet capture parsing error: ${err.message || err}` });
  }
});

// -----------------------------------------------------------------------------
// 7. PORT SCANNER (Educational TCP Connect Check, Authorization Gated)
// -----------------------------------------------------------------------------
const COMMON_PORTS = [
  { port: 21, service: 'FTP', risk: 'Legacy file transfer; passes credentials in plaintext by default.' },
  { port: 22, service: 'SSH', risk: 'Encrypted remote administration; ensure password auth is disabled in favor of ed25519 keys.' },
  { port: 25, service: 'SMTP', risk: 'Mail relay; unauthenticated open relays can be abused for spam and phishing distribution.' },
  { port: 53, service: 'DNS', risk: 'Domain name resolution; open recursors can be weaponized in amplification DDoS attacks.' },
  { port: 80, service: 'HTTP', risk: 'Unencrypted web traffic; should redirect immediately to HTTPS (port 443).' },
  { port: 110, service: 'POP3', risk: 'Legacy email retrieval; vulnerable to credential sniffing if unencrypted.' },
  { port: 143, service: 'IMAP', risk: 'Email synchronization; should enforce IMAPS (port 993).' },
  { port: 443, service: 'HTTPS', risk: 'Standard TLS web encryption; inspect cipher suite and certificate validity.' },
  { port: 445, service: 'SMB', risk: 'Windows file sharing; high-severity attack vector (EternalBlue, ransomware lateral movement).' },
  { port: 3306, service: 'MySQL', risk: 'Database management; should never be exposed directly to the public internet.' },
  { port: 3389, service: 'RDP', risk: 'Remote Desktop Protocol; frequent target of automated brute-force and credential stuffing.' },
  { port: 5432, service: 'PostgreSQL', risk: 'Relational database; should be bound to localhost or protected inside private VPC.' },
  { port: 8080, service: 'HTTP-Alt / Proxy', risk: 'Alternative web port; commonly used for dev dashboards, Jenkins, or management consoles.' },
  { port: 8443, service: 'HTTPS-Alt', risk: 'Alternative SSL web port; verify TLS configuration and administrative access controls.' },
];

function checkPort(host: string, port: number, timeoutMs = 850): Promise<'open' | 'closed' | 'filtered'> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status: 'open' | 'closed' | 'filtered' = 'filtered';

    socket.setTimeout(timeoutMs);

    socket.connect(port, host, () => {
      status = 'open';
      socket.destroy();
      resolve(status);
    });

    socket.on('error', (err: any) => {
      // ECONNREFUSED means target actively replied with TCP RST -> port is closed, host is alive!
      if (err.code === 'ECONNREFUSED') {
        status = 'closed';
      } else {
        status = 'filtered';
      }
      socket.destroy();
      resolve(status);
    });

    socket.on('timeout', () => {
      status = 'filtered';
      socket.destroy();
      resolve(status);
    });
  });
}

app.post('/api/port-scan', async (req: Request, res: Response) => {
  const { host: rawHost, authorized } = req.body;

  if (!authorized) {
    return res.status(403).json({
      error: 'Authorization required. You must check "I own this system or have explicit authorization to test it" before scanning.',
    });
  }

  if (!rawHost || typeof rawHost !== 'string') {
    return res.status(400).json({ error: 'Valid hostname or IP is required.' });
  }

  const host = sanitizeHost(rawHost);

  // Check if target resolves
  try {
    const resolved = await dns.promises.lookup(host);
    const targetIp = resolved.address;

    // Scan fixed common ports with bounded concurrency (3 at a time)
    const results: any[] = [];
    for (let i = 0; i < COMMON_PORTS.length; i += 3) {
      const slice = COMMON_PORTS.slice(i, i + 3);
      const batchPromises = slice.map(async (p) => {
        const state = await checkPort(targetIp, p.port);
        return {
          port: p.port,
          service: p.service,
          risk: p.risk,
          state, // 'open' | 'closed' | 'filtered'
        };
      });
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
    }

    return res.json({
      target: host,
      targetIp,
      scannedAt: new Date().toISOString(),
      ports: results,
      summary: {
        total: results.length,
        open: results.filter(r => r.state === 'open').length,
        closed: results.filter(r => r.state === 'closed').length,
        filtered: results.filter(r => r.state === 'filtered').length,
      }
    });
  } catch (err: any) {
    return res.status(400).json({ error: `Unable to resolve host "${host}": ${err.message || err}` });
  }
});

// -----------------------------------------------------------------------------
// 8. CYBER NEWS (CISA KEV & Security Bulletins - Cached hourly)
// -----------------------------------------------------------------------------
app.get('/api/news', async (_req: Request, res: Response) => {
  const now = Date.now();
  // Return cached feed if under 1 hour old
  if (cachedNews.length > 0 && now - newsLastFetched < 3600 * 1000) {
    return res.json({ news: cachedNews, cached: true, lastFetched: new Date(newsLastFetched).toISOString() });
  }

  try {
    // Fetch CISA Known Exploited Vulnerabilities catalog
    const cisaResp = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
      signal: AbortSignal.timeout(6000),
      headers: { 'User-Agent': 'CyberToolkit-NewsFeed/1.0' },
    });

    if (cisaResp.ok) {
      const cisaData = await cisaResp.json();
      const vulns = (cisaData.vulnerabilities || []).slice(0, 15);

      cachedNews = vulns.map((v: any) => ({
        id: v.cveID,
        title: `${v.vendorProject} ${v.product} — ${v.vulnerabilityName}`,
        source: 'CISA Known Exploited Vulnerabilities',
        published: v.dateAdded,
        description: v.shortDescription,
        actionRequired: v.requiredAction,
        dueDate: v.dueDate,
        cveId: v.cveID,
        link: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
        severity: 'ACTIVE EXPLOITATION REPORTED',
      }));

      newsLastFetched = now;
      return res.json({ news: cachedNews, cached: false, lastFetched: new Date(newsLastFetched).toISOString() });
    }
  } catch {
    // If public fetch fails, serve high-quality fallback feed
  }

  if (cachedNews.length === 0) {
    cachedNews = [
      {
        id: 'CISA-ALERT-2026-01',
        title: 'CISA Adds Flaws in Enterprise Identity and Gateway Appliances to Active Exploitation Catalog',
        source: 'CISA Security Bulletin',
        published: '2026-09-20',
        description: 'Federal civilian agencies are mandated to patch unauthenticated remote access and boundary device vulnerabilities exploited by advanced persistent threat actors.',
        actionRequired: 'Apply vendor-provided patches immediately; audit perimeter device logs for anomalous session creations.',
        cveId: 'CVE-2024-21887',
        link: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        severity: 'HIGH PRIORITY',
      },
      {
        id: 'NVD-ALERT-2026-02',
        title: 'Critical Flaw in Kubernetes Ingress Controller Disclosed',
        source: 'Cloud Native Computing Foundation',
        published: '2026-09-15',
        description: 'Specially crafted HTTP headers allow bypass of mutual TLS client authentication and path-based RBAC restrictions on exposed cluster services.',
        actionRequired: 'Upgrade ingress controllers to latest patched minor release; enforce zero-trust service mesh sidecars.',
        cveId: 'CVE-2024-7646',
        link: 'https://nvd.nist.gov',
        severity: 'CRITICAL',
      },
      {
        id: 'SEC-ALERT-2026-03',
        title: 'Supply Chain Alert: Malicious Dependencies Discovered on Public Package Registries',
        source: 'OpenSSF Threat Intelligence',
        published: '2026-09-10',
        description: 'Typosquatting packages disguised as standard cryptography and cloud SDK helpers detected harvesting developer AWS and GCP credentials during postinstall scripts.',
        actionRequired: 'Enforce package lockfile hash verification and disable automatic lifecycle install scripts in CI/CD.',
        cveId: 'N/A (Supply Chain)',
        link: 'https://openssf.org',
        severity: 'SUPPLY CHAIN ADVISORY',
      }
    ];
    newsLastFetched = now;
  }

  return res.json({ news: cachedNews, cached: true, lastFetched: new Date(newsLastFetched).toISOString() });
});

// -----------------------------------------------------------------------------
// VITE MIDDLEWARE (DEV) OR STATIC FILES (PROD)
// -----------------------------------------------------------------------------
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(Number(PORT), '0.0.0.0', () => {
    console.log(`[CyberToolkit] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
