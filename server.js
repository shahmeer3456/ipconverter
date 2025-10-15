import express from "express";
import cors from "cors";
import dns from "node:dns/promises";
import tls from "node:tls";
import fetch from "node-fetch";

const app = express();
app.use(cors());
app.use(express.json());

const WHOIS_API_KEY = "at_j5Y7oTdKHxoJtotgj4AAK9heyab0F";
const WHOIS_API_URL = "https://reverse-ip.whoisxmlapi.com/api/v1";

// --- Helpers ---

async function ptrLookup(ip) {
  try {
    return await dns.reverse(ip);
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
        resolve(Array.from(names));
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

async function domainToIp(domain) {
  try {
    const addresses = await dns.lookup(domain, { all: true });
    return addresses.map((a) => a.address);
  } catch {
    return [];
  }
}

// --- Routes ---

//  IP → Domain Name
app.get("/api/reverse-ip", async (req, res) => {
  const { ip } = req.query;
  console.log("ip:",ip);
  if (!ip) return res.status(400).json({ error: "IP address is required" });

  // Check if it's a single IP address (e.g., 104.18.113.47)
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    const [ptr, certNames, apiDomains] = await Promise.all([
      ptrLookup(ip),
      getTlsCertNames(ip),
      reverseIpApi(ip),
    ]);

    // If apiDomains is empty, use certNames as the domains to return
    const domainsToReturn = apiDomains.length > 0 ? apiDomains : certNames;
    console.log("{ ip, ptr, certNames, apiDomains: domainsToReturn }:",{ ip, ptr, certNames, apiDomains:domainsToReturn })

    return res.json({ ip, ptr, certNames, apiDomains: domainsToReturn });
  }

  const [ptr, certNames, apiDomains] = await Promise.all([
    ptrLookup(ip),
    getTlsCertNames(ip),
    reverseIpApi(ip),
  ]);

  // If apiDomains is empty, use certNames as the domains to return
  const domainsToReturn = apiDomains.length > 0 ? apiDomains : certNames;
  console.log("{ ip, ptr, certNames, apiDomains: domainsToReturn }:",{ ip, ptr, certNames, apiDomains:domainsToReturn })

  res.json({ ip, ptr, certNames, apiDomains: domainsToReturn });
});

// Domain → IP Address
app.get("/api/domain-to-ip", async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: "Domain name is required" });

  const ips = await domainToIp(domain);
  console.log("ips:",ips);
  res.json({ domain, ips });
});

const PORT = 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));



