const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const cheerio = require('cheerio');
const dns = require('dns').promises;
const net = require('net');

const app = express();
app.use(cors());

const BLOCKED_HOSTNAMES = new Set(['localhost', '0.0.0.0', '0', 'broadcasthost']);

function isPrivateOrLoopbackIp(ip) {
  const family = net.isIP(ip);
  if (!family) return false;
  if (family === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateOrLoopbackIp(mapped[1]);
  const firstHextet = parseInt(lower.split(':')[0] || '0', 16);
  if (Number.isFinite(firstHextet)) {
    if ((firstHextet & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
    if ((firstHextet & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  }
  return false;
}

// Pre-flight only — not DNS-rebinding-proof and does not re-check redirect targets.
async function validateUrl(url) {
  let parsed;
  try { parsed = new URL(url); } catch { return 'invalid URL'; }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return 'scheme not allowed';
  const host = parsed.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith('.localhost')) return 'host not allowed';
  if (net.isIP(host)) {
    return isPrivateOrLoopbackIp(host) ? 'address not allowed' : null;
  }
  let addrs;
  try { addrs = await dns.lookup(host, { all: true }); } catch { return 'DNS lookup failed'; }
  if (addrs.some(a => isPrivateOrLoopbackIp(a.address))) return 'address not allowed';
  return null;
}

app.get('/meta', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'No URL provided' });

  const blockReason = await validateUrl(url);
  if (blockReason) return res.status(400).json({ error: 'URL not allowed' });

  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RichLinkBot/1.0)' },
      timeout: 8000,
      size: 5_000_000,
      follow: 3
    });
    const html = await response.text();
    const $ = cheerio.load(html);

    const get = (prop) =>
      $(`meta[property="${prop}"]`).attr('content') ||
      $(`meta[name="${prop}"]`).attr('content') || '';

    const title = get('og:title') || $('title').text() || '';
    const description = get('og:description') || get('description') || '';
    const image = get('og:image') || '';
    const siteName = get('og:site_name') || '';
    const domain = new URL(url).hostname;

    res.json({ title, description, image, domain, siteName });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on port ${PORT}`));
