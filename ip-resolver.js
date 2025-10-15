
import dns from 'dns/promises';
import express from 'express';
import cors from 'cors';
import { Netmask } from 'netmask';
import tls from 'tls';
import fetch from 'node-fetch';
import { getDomain } from 'tldts';

const app = express();
app.use(cors());
app.use(express.json());

const WHOIS_API_KEY = "at_j5Y7oTdKHxoJtotgj4AAK9heyab0F";
const WHOIS_API_URL = "https://reverse-ip.whoisxmlapi.com/api/v1";

// --- Helper functions for single IP resolution ---

async function ptrLookup(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    // Extract domain names from hostnames
    return Array.from(new Set(
      hostnames.map(extractDomainName).filter(Boolean)
    ));
  } catch {
    return [];
  }
}

function getTlsCertNames(ip, timeout = 4000) {
  return new Promise((resolve) => {
    const options = {
      host: ip,
      port: 443,
      servername: ip,
      rejectUnauthorized: false,
      timeout,
    };

    const socket = tls.connect(options, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const names = new Set();

        if (cert.subject && cert.subject.CN) names.add(cert.subject.CN);

        if (cert.subjectaltname) {
          const parts = cert.subjectaltname.split(",").map((p) => p.trim());
          for (const part of parts) {
            if (part.startsWith("DNS:")) names.add(part.substring(4));
          }
        }

        socket.end();
        // Extract domain names from certificate names
        const domains = Array.from(new Set(
          Array.from(names).map(extractDomainName).filter(Boolean)
        ));
        resolve(domains);
      } catch {
        socket.destroy();
        resolve([]);
      }
    });

    socket.on("error", () => resolve([]));
    socket.on("timeout", () => {
      socket.destroy();
      resolve([]);
    });
  });
}

async function reverseIpApi(ip) {
  try {
    const res = await fetch(`${WHOIS_API_URL}?apiKey=${WHOIS_API_KEY}&ip=${ip}`);
    const data = await res.json();
    return data.result?.domains || [];
  } catch {
    return [];
  }
}

// --- Verify that a domain is real and currently resolves to the given IP ---
async function verifyDomainLive(domain, ip) {
  try {
    // 1. DNS A/AAAA lookup
    const [aRecords, aaaaRecords] = await Promise.all([
      dns.resolve(domain, 'A').catch(() => []),
      dns.resolve(domain, 'AAAA').catch(() => [])
    ]);
    const allIPs = [...aRecords, ...aaaaRecords];

    if (allIPs.length === 0) return false;

    // 2. Check if target IP matches any A record
    if (!allIPs.includes(ip)) return false;

    // 3. Optional: quick HTTP HEAD check (confirm it's actually alive)
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2500);
      const res = await fetch(`http://${domain}`, {
        method: 'HEAD',
        signal: controller.signal,
      }).catch(() => null);
      clearTimeout(timeout);

      if (!res || !res.ok) {
        return false; // not reachable or invalid domain
      }
    } catch {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

// Helper function to check if a domain is known infrastructure/hosting
function isKnownInfrastructureDomain(hostname) {
  // Known hosting/infrastructure domain patterns
  const infrastructureDomains = [
    // AWS patterns
    /\.amazonaws\.com$/,
    /\.compute-\d+\.amazonaws\.com$/,
    /\.ec2\.internal$/,
    
    // Google Cloud patterns
    /\.googleusercontent\.com$/,
    /\.googleapis\.com$/,
    /\.c\.googlers\.com$/,
    
    // Microsoft Azure patterns
    /\.cloudapp\.net$/,
    /\.azurewebsites\.net$/,
    /\.blob\.core\.windows\.net$/,
    
    // DigitalOcean patterns
    /\.digitalocean\.com$/,
    /\.droplet\.digitalocean\.com$/,
    
    // Other major hosting providers
    /\.hostgator\.com$/,
    /\.godaddy\.com$/,
    /\.bluehost\.com$/,
    /\.dreamhost\.com$/,
    /\.siteground\.com$/,
    /\.namecheap\.com$/,
    
    // Generic hosting patterns
    /\.hosting\.com$/,
    /\.webhost\.net$/,
    /\.serverfarm\.com$/,
    /\.datacenter\.net$/,
    /\.cloud\.net$/,
    /\.vps\.net$/,
    
    // ISP patterns
    /\.comcast\.net$/,
    /\.verizon\.net$/,
    /\.att\.net$/,
    /\.charter\.com$/,
    /\.cox\.net$/,
    /\.rr\.com$/,
    /\.roadrunner\.com$/,
    
    // Generic infrastructure TLDs and patterns
    /\.internal$/,
    /\.local$/,
    /\.lan$/,
    /\.corp$/,
    
    // Reverse DNS patterns
    /\d+-\d+-\d+-\d+\./,  // IP-like patterns anywhere in domain
    
    // Known generic hosting domain names
    /^host-[a-z0-9]+\.net$/,      // Specifically catch host-h.net, etc.
    /^server-[a-z0-9]+\.(com|net|org)$/,
    /^vm-[a-z0-9]+\.(com|net|org)$/,
    /^vps-[a-z0-9]+\.(com|net|org)$/,
  ];
  
  // Check against all infrastructure patterns
  for (const pattern of infrastructureDomains) {
    if (pattern.test(hostname)) {
      return true;
    }
  }
  
  // Check if the domain name itself indicates infrastructure
  const parts = hostname.split('.');
  if (parts.length >= 2) {
    const domainPart = parts[parts.length - 2].toLowerCase();
    
    // Known infrastructure domain names
    const infrastructureNames = [
      'hosting', 'webhost', 'serverfarm', 'datacenter', 'cloudhost',
      'vpshost', 'dedicated', 'shared', 'reseller', 'provider',
      'infrastructure', 'server', 'compute', 'instance', 'node',
      'cluster', 'grid', 'farm', 'rack', 'cabinet', 'facility'
    ];
    
    if (infrastructureNames.includes(domainPart)) {
      return true;
    }
  }
  
  return false;
}

// Helper function to extract domain name from hostname
function extractDomainName(hostname) {
  if (!hostname) return null;
  
  // Strip trailing dot and lowercase
  const host = hostname.endsWith('.') ? hostname.slice(0, -1).toLowerCase() : hostname.toLowerCase();
  
  // Skip reverse DNS entries (in-addr.arpa, ip6.arpa)
  if (host.includes('.in-addr.arpa') || host.includes('.ip6.arpa')) {
    return null;
  }
  
  // Skip localhost and private network entries
  if (host === 'localhost' || host.startsWith('localhost.')) {
    return null;
  }
  
  // Skip generic hosting patterns and server hostnames
  const genericPatterns = [
    // Basic hosting patterns
    /^host-[a-z0-9]+\./,           // host-a., host-1., host-h.
    /^server-[a-z0-9-]+\./,       // server-1., server-alpha., server-web-01.
    /^srv-[a-z0-9-]+\./,          // srv-1., srv-001., srv-web.
    /^node-[a-z0-9-]+\./,         // node-1., node-east., node-prod.
    /^vm-[a-z0-9-]+\./,           // vm-123., vm-prod., vm-web.
    /^vps-[a-z0-9-]+\./,          // vps-789., vps-web., vps-db.
    
    // Cloud/Infrastructure patterns
    /^ec2-[0-9-]+\./,             // ec2-1-2-3-4.
    /^ip-[0-9-]+\./,              // ip-10-0-1-100.
    /^static-[0-9-]+\./,          // static-192-168-1-1.
    /^dynamic-[0-9-]+\./,         // dynamic-ip-123-456.
    /^pool-[0-9-]+\./,            // pool-192-168-1-1.
    /^dsl-line-[0-9-]+\./,        // dsl-line-123.
    /^cable-modem-[0-9-]+\./,     // cable-modem-456.
    
    // Datacenter patterns
    /^dc[0-9]+-[a-z0-9-]+\./,     // dc1-server-01.
    /^rack-[0-9]+-[a-z0-9-]+\./,  // rack-5-slot-3.
    /^cabinet-[a-z0-9-]+\./,      // cabinet-a-unit-12.
    /^pod-[0-9]+-[a-z0-9-]+\./,   // pod-1-host-5.
    
    // Service-specific patterns
    /^web-[0-9]+\./,              // web-1., web-2.
    /^db-[a-z0-9-]+\./,           // db-primary., db-backup.
    /^mail-relay-[0-9]+\./,       // mail-relay-1.
    /^cdn-edge-[0-9]+\./,         // cdn-edge-01.
    
    // Geographic/Location patterns
    /^[a-z]+-[a-z]+-[0-9]+-[a-z0-9-]+\./, // us-east-1-host., eu-west-2-node.
    /^[a-z]{2,3}-datacenter-[0-9]+\./, // nyc-datacenter-5.
    /^[a-z]{2,3}-[0-9]+-[a-z0-9-]+\./, // asia-1-server.
    
    // ISP/Hosting provider patterns
    /^customer-[0-9]+\./,         // customer-123.
    /^shared-[0-9]+\./,           // shared-456.
    /^dedicated-[0-9]+\./,        // dedicated-789.
    /^reseller-[0-9]+\./,         // reseller-001.
    
    // IP-like hostname patterns
    /^[0-9]+-[0-9]+-[0-9]+-[0-9]+\./, // 192-168-1-1., 123-456-789-012.
    /^[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}\./, // More specific IP patterns
    
    // Short generic patterns
    /^[a-z]{1,3}[0-9]{1,6}\./,    // h48., srv123., a1., web2.
    /^[0-9]{1,4}[a-z]{1,3}\./,    // 123srv., 456web.
    
    // Standard service patterns
    /^mail[0-9]*\./,              // mail., mail1., mail123.
    /^mx[0-9]*\./,                // mx., mx1., mx2.
    /^ns[0-9]*\./,                // ns., ns1., ns2.
    /^www[0-9]*\./,               // www., www1., www2.
    /^ftp[0-9]*\./,               // ftp., ftp1.
    /^smtp[0-9]*\./,              // smtp., smtp1.
    /^pop[0-9]*\./,               // pop., pop3.
    /^imap[0-9]*\./,              // imap., imap4.
    
    // AWS/Cloud specific patterns
    /^compute-[0-9-]+\./,         // compute-1.
    /^instance-[0-9-]+\./,        // instance-123.
    /^worker-[0-9-]+\./,          // worker-01.
    /^master-[0-9-]+\./,          // master-01.
    
    // Generic alphanumeric patterns that look like infrastructure
    /^[a-z0-9]{1,2}-[a-z0-9]{1,8}\./,  // h-net., a1-b2., vm-web.
    /^[a-z]{1,4}[0-9]{1,4}-[a-z0-9]{1,8}\./,  // host1-web., srv2-db.
  ];
  
  // Special check for exact "host-h.net" pattern and similar
  if (/^host-[a-z0-9]+\.net$/.test(host) || 
      /^host-[a-z0-9]+\.com$/.test(host) ||
      /^host-[a-z0-9]+\.org$/.test(host)) {
    return null; // Skip host-h.net, host-1.com, etc.
  }
  
  // Check if hostname matches any generic pattern
  for (const pattern of genericPatterns) {
    if (pattern.test(host)) {
      return null; // Skip generic hostnames
    }
  }
  
  // Check for known hosting/infrastructure domain patterns
  if (isKnownInfrastructureDomain(host)) {
    return null;
  }
  
  // Extract registrable domain using public suffix list
  const domain = getDomain(host);
  
  // Additional validation: ensure it's a proper domain name and not just a hostname
  if (domain && 
      /^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain) && 
      !/^\d+\.\d+\.\d+\.\d+$/.test(domain) && 
      !domain.includes('in-addr') &&
      domain.split('.').length >= 2) {
    
    // Extra check: if the original hostname is significantly different from the domain
    // and looks like a server hostname, skip it
    if (host !== domain) {
      const hostParts = host.split('.');
      const domainParts = domain.split('.');
      
      // If hostname has many more parts than domain, it's likely a server hostname
      if (hostParts.length > domainParts.length + 1) {
        const subdomain = hostParts.slice(0, hostParts.length - domainParts.length).join('.');
        
        // Check if subdomain looks like a server/hosting identifier
        const serverPatterns = [
          /^[a-z0-9]{1,8}$/,        // Short alphanumeric like "h", "srv1"
          /^[0-9]+$/,               // Pure numbers like "123"
          /^[a-z]+[0-9]+$/,         // Letter+numbers like "host1", "server2"
          /^[a-z0-9]+-[a-z0-9]+$/,  // Hyphenated patterns
          /^host-[a-z0-9]+$/,       // host-h, host-1, etc.
          /^server-[a-z0-9-]+$/,    // server-web-01, etc.
          /^vm-[a-z0-9-]+$/,        // vm-prod-123, etc.
          /^vps-[a-z0-9-]+$/,       // vps-web, etc.
          /^node-[a-z0-9-]+$/,      // node-east, etc.
        ];
        
        for (const pattern of serverPatterns) {
          if (pattern.test(subdomain)) {
            return null; // Skip server-like subdomains
          }
        }
      }
    }
    
    // Final check: even if domain extraction worked, verify it's not an infrastructure domain
    if (isKnownInfrastructureDomain(domain)) {
      return null;
    }
    
    // Final check: filter out known hosting domain patterns
    if (isKnownHostingDomain(domain)) {
      return null;
    }
    
    return domain;
  }
  
  // If getDomain doesn't extract a different domain, try manual extraction
  const parts = host.split('.');
  if (parts.length >= 2) {
    // Take last 2 parts if they form a valid domain
    const lastTwo = parts.slice(-2).join('.');
    if (/^[a-z0-9-]+\.[a-z]{2,}$/.test(lastTwo) && 
        !lastTwo.includes('in-addr') &&
        !lastTwo.includes('arpa')) {
      
      // Additional check for generic patterns in the domain itself
      const domainName = parts[parts.length - 2];
      const infrastructureKeywords = [
        'host', 'server', 'mail', 'mx', 'ns', 'www', 'ftp', 'smtp', 'pop', 'imap',
        'vm', 'vps', 'node', 'static', 'dynamic', 'hosting', 'webhost', 'serverfarm',
        'datacenter', 'cloudhost', 'vpshost', 'dedicated', 'shared', 'reseller',
        'provider', 'infrastructure', 'compute', 'instance', 'cluster', 'grid',
        'farm', 'rack', 'cabinet', 'facility'
      ];
      
      // Check if domain name is infrastructure-related
      const isInfrastructure = infrastructureKeywords.some(keyword => 
        domainName === keyword || 
        new RegExp(`^${keyword}[0-9]*$`).test(domainName) ||
        new RegExp(`^${keyword}-[a-z0-9]+$`).test(domainName)
      );
      
      if (!isInfrastructure && !isKnownInfrastructureDomain(lastTwo)) {
        return lastTwo;
      }
    }
    
    // Take last 3 parts if it looks like subdomain.domain.tld
    if (parts.length >= 3) {
      const lastThree = parts.slice(-3).join('.');
      if (/^[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}$/.test(lastThree) && 
          !lastThree.includes('in-addr') &&
          !lastThree.includes('arpa')) {
        
        // Check if it's not a generic pattern
        const domainName = parts[parts.length - 2];
        const infrastructureKeywords = [
          'host', 'server', 'mail', 'mx', 'ns', 'www', 'ftp', 'smtp', 'pop', 'imap',
          'vm', 'vps', 'node', 'static', 'dynamic', 'hosting', 'webhost', 'serverfarm',
          'datacenter', 'cloudhost', 'vpshost', 'dedicated', 'shared', 'reseller',
          'provider', 'infrastructure', 'compute', 'instance', 'cluster', 'grid',
          'farm', 'rack', 'cabinet', 'facility'
        ];
        
        // Check if domain name is infrastructure-related
        const isInfrastructure = infrastructureKeywords.some(keyword => 
          domainName === keyword || 
          new RegExp(`^${keyword}[0-9]*$`).test(domainName) ||
          new RegExp(`^${keyword}-[a-z0-9]+$`).test(domainName)
        );
        
        if (!isInfrastructure && !isKnownInfrastructureDomain(lastThree)) {
          return lastThree;
        }
      }
    }
  }
  
  return null;
}

// Helper function to identify known hosting/infrastructure domains
function isKnownHostingDomain(domain) {
  if (!domain) return false;
  
  const hostingPatterns = [
    // Exact matches for common hosting domains
    'host-h.net',
    'host-a.net',
    'host-b.net',
    'host-c.net',
    'host-d.net',
    'host-e.net',
    'host-f.net',
    'host-g.net',
    'host-i.net',
    'host-j.net',
    
    // Pattern-based checks
    /^host-[a-z0-9]+\.(net|com|org)$/,
    /^server-[a-z0-9]+\.(net|com|org)$/,
    /^vm-[a-z0-9]+\.(net|com|org)$/,
    /^vps-[a-z0-9]+\.(net|com|org)$/,
    /^[a-z]{1,3}[0-9]{1,6}\.(net|com|org)$/,  // Short patterns like h1.net, srv123.com
    /^[0-9]+-[0-9]+-[0-9]+-[0-9]+\.(net|com|org)$/,  // IP-like patterns
    
    // Generic cloud/hosting provider patterns
    /.*\.amazonaws\.com$/,
    /.*\.googleusercontent\.com$/,
    /.*\.cloudflare\.com$/,
    /.*\.digitalocean\.com$/,
    /.*\.linode\.com$/,
    /.*\.vultr\.com$/,
    /.*\.hetzner\.(com|de)$/,
    /.*\.ovh\.(com|net)$/,
  ];
  
  const lowerDomain = domain.toLowerCase();
  
  // Check exact matches
  if (hostingPatterns.includes(lowerDomain)) {
    return true;
  }
  
  // Check regex patterns
  for (const pattern of hostingPatterns) {
    if (pattern instanceof RegExp && pattern.test(lowerDomain)) {
      return true;
    }
  }
  
  return false;
}

// Function to expand CIDR notation to individual IPs
function expandCIDR(cidr) {
    const ips = [];
    try {
        const subnet = new Netmask(cidr);
        const startIP = subnet.base;
        const endIP = subnet.broadcast;
        
        const start = ipToLong(startIP);
        const end = ipToLong(endIP);
        
        // Limit to prevent memory issues (max 1000 IPs per range)
        const limit = Math.min(end - start + 1, 1000);
        
        for (let i = 0; i < limit; i++) {
            ips.push(longToIp(start + i));
        }
    } catch (error) {
        console.error(`Error expanding CIDR ${cidr}:`, error.message);
    }
    return ips;
}

// Convert IP to long number
function ipToLong(ip) {
    const parts = ip.split('.');
    return (parseInt(parts[0]) << 24) + 
           (parseInt(parts[1]) << 16) + 
           (parseInt(parts[2]) << 8) + 
           parseInt(parts[3]);
}

// Convert long number to IP
function longToIp(long) {
    return [
        (long >>> 24) & 0xFF,
        (long >>> 16) & 0xFF,
        (long >>> 8) & 0xFF,
        long & 0xFF
    ].join('.');
}

// Perform reverse DNS lookup with timeout
async function reverseLookup(ip, timeout = 2000) {
  try {
    // Perform PTR lookup
    const ptrs = await dns.reverse(ip);

    // Convert PTR hostnames to registrable domains (eTLD+1)
    const domains = Array.from(new Set(
      (ptrs || [])
        .map((h) => {
          if (!h) return null;
          
          // Strip trailing dot and lowercase
          const host = h.endsWith('.') ? h.slice(0, -1).toLowerCase() : h.toLowerCase();
          
          // Skip reverse DNS entries (in-addr.arpa, ip6.arpa)
          if (host.includes('.in-addr.arpa') || host.includes('.ip6.arpa')) {
            return null;
          }
          
          // Skip localhost and private network entries
          if (host === 'localhost' || host.startsWith('localhost.')) {
            return null;
          }
          
          // Use the same extractDomainName function for consistency
          return extractDomainName(h);
        })
        .filter(Boolean)
    ));

    if (domains.length > 0) {
      return {
        ip,
        domains,
        status: 'resolved'
      };
    }
    return {
      ip,
      domains: [],
      status: 'no_domain'
    };
  } catch (error) {
    return {
      ip,
      domains: [],
      status: 'error',
      error: error.message
    };
  }
}

// Process IP ranges with rate limiting
async function processIPRanges(ranges, progressCallback) {
    const results = [];
    const batchSize = 10; // Process 10 IPs concurrently
    
    for (const range of ranges) {
        console.log(`Processing range: ${range}`);
        const ips = expandCIDR(range);
        
        for (let i = 0; i < ips.length; i += batchSize) {
            const batch = ips.slice(i, i + batchSize);
            const batchResults = await Promise.all(
                batch.map(ip => reverseLookup(ip))
            );
            
            // Filter only successful resolutions
            const successfulResults = batchResults.filter(
                result => result.domains && result.domains.length > 0
            );
            
            results.push(...successfulResults);
            
            // Report progress
            if (progressCallback) {
                const progress = Math.round(((i + batch.length) / ips.length) * 100);
                progressCallback({
                    range,
                    progress,
                    found: successfulResults.length
                });
            }
            
            // Small delay to avoid overwhelming DNS servers
            await new Promise(resolve => setTimeout(resolve, 100));
        }
    }
    
    return results;
}

// Single IP reverse lookup API endpoint with live DNS verification
app.get("/api/reverse-ip", async (req, res) => {
  const { ip } = req.query;
  console.log("Single IP lookup for:", ip);

  if (!ip) return res.status(400).json({ error: "IP address is required" });

  // Collect possible candidates
  const [ptr, certNames, apiDomains] = await Promise.all([
    ptrLookup(ip),
    getTlsCertNames(ip),
    reverseIpApi(ip),
  ]);

  // Merge candidates and extract domain names from API results
  const processedApiDomains = Array.from(new Set(
    apiDomains.map(extractDomainName).filter(Boolean)
  ));

  const allCandidates = Array.from(
    new Set([...ptr, ...certNames, ...processedApiDomains])
  ).filter(Boolean);

  console.log("Checking candidates:", allCandidates);

  // Filter only domains that still exist and point to this IP
  const verifiedDomains = [];
  for (const domain of allCandidates) {
    const ok = await verifyDomainLive(domain, ip);
    if (ok) verifiedDomains.push(domain);
  }

  console.log("Verified domains:", verifiedDomains);

  res.json({
    ip,
    ptr,
    certNames,
    apiDomains: processedApiDomains,
    verifiedDomains,
    count: verifiedDomains.length,
  });
});

// Batch IP ranges resolution API endpoint
app.post('/resolve-ips', async (req, res) => {
    const { ranges } = req.body;
    
    if (!ranges || !Array.isArray(ranges)) {
        return res.status(400).json({ error: 'Invalid input. Expected array of IP ranges.' });
    }
    
    // Set up SSE for progress updates
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
    });
    
    const progressCallback = (progress) => {
        res.write(`data: ${JSON.stringify({ type: 'progress', ...progress })}\n\n`);
    };
    
    try {
        const results = await processIPRanges(ranges, progressCallback);
        res.write(`data: ${JSON.stringify({ type: 'complete', results })}\n\n`);
    } catch (error) {
        res.write(`data: ${JSON.stringify({ type: 'error', error: error.message })}\n\n`);
    } finally {
        res.end();
    }
});

// Serve static files (for the frontend)
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});