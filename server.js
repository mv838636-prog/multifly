const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createPaymentRoutes, hasValidRazorpayKeys } = require('./lib/payments');
const registerAuthRoutes = require('./lib/auth-routes');

const app = express();
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://checkout.razorpay.com'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      fontSrc: ["'self'", 'data:'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", 'https://api.razorpay.com', 'https://checkout.razorpay.com'],
      frameSrc: ["'self'", 'https://checkout.razorpay.com', 'https://api.razorpay.com'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'", 'https://checkout.razorpay.com']
    }
  }
}));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use('/api/razorpay/webhook', express.raw({ type: 'application/json', limit: '100kb' }));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d',
  setHeaders(res, filePath) {
    if (/\.(html|js|css)$/i.test(filePath)) res.setHeader('Cache-Control', 'no-cache');
  }
}));

const DATA = path.join(__dirname, 'data');
fs.mkdirSync(DATA, { recursive: true });
const save = (file, row) =>
  fs.appendFile(path.join(DATA, file), JSON.stringify({ at: new Date().toISOString(), ...row }) + '\n', err => {
    if (err) console.error(`Could not append ${file}:`, err.message);
  });

// Small in-memory rate limit: 30 requests per minute per IP on /api
const hits = new Map();
app.use('/api', (req, res, next) => {
  const now = Date.now(), h = (hits.get(req.ip) || []).filter(t => now - t < 60000);
  h.push(now); hits.set(req.ip, h);
  h.length > 30 ? res.status(429).json({ error: 'Too many requests. Try again in a minute.' }) : next();
});
const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many payment attempts. Please wait and try again.' }
});
createPaymentRoutes(app, express, { env: process.env, projectDir: __dirname, paymentLimiter });
registerAuthRoutes(app, __dirname);
app.get('/contact', (_req, res) => res.redirect(301, '/contact.html'));

const clean = (v, n = 200) => String(v || '').trim().slice(0, n);
const okPhone = v => /^[0-9+\-\s]{10,15}$/.test(v);

app.post('/api/lead', (req, res) => {
  const body = req.body || {};
  const lead = {
    name: clean(body.name, 80), phone: clean(body.phone, 15), email: clean(body.email),
    service: clean(body.service, 60), message: clean(body.message, 600)
  };
  if (!lead.name || !okPhone(lead.phone)) return res.status(400).json({ error: 'Add your name and a valid phone number.' });
  fs.appendFile(path.join(DATA, 'leads.jsonl'), JSON.stringify({ at: new Date().toISOString(), ...lead }) + '\n', err => {
    if (err) {
      console.error('Could not save lead:', err.message);
      return res.status(500).json({ error: 'Could not save your enquiry. Please try again.' });
    }
    res.json({ ok: true });
  });
});

// SSRF Protection Helper
const isPrivateIp = (ip) => {
  if (!ip) return true;
  if (ip === '::1' || ip === 'localhost') return true;
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  const p = ip.split('.').map(Number);
  if (p.length === 4) {
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
    return false;
  }
  const low = ip.toLowerCase();
  return low.startsWith('fc') || low.startsWith('fd') || low.startsWith('fe80');
};

// PHASE 5: Free AI Visibility Checker Endpoint
app.post('/api/visibility-check', async (req, res) => {
  const businessName = clean(req.body.businessName, 120);
  let rawUrl = clean(req.body.url, 250);
  const niche = clean(req.body.niche, 80);

  if (!rawUrl) {
    return res.status(400).json({ error: 'Please enter a valid website URL.' });
  }

  if (!/^https?:\/\//i.test(rawUrl)) {
    rawUrl = 'https://' + rawUrl;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return res.status(400).json({ error: 'Only HTTP and HTTPS URLs are supported.' });
    }
  } catch (_e) {
    return res.status(400).json({ error: 'Invalid URL format.' });
  }

  // SSRF Protection: Resolve hostname and verify IP is public
  try {
    const dns = require('dns').promises;
    const lookup = await dns.lookup(parsedUrl.hostname);
    if (isPrivateIp(lookup.address)) {
      return res.status(400).json({ error: 'Access to private or internal addresses is blocked.' });
    }
  } catch (err) {
    return res.status(400).json({ error: 'Could not resolve domain name. Please check spelling.' });
  }

  // Fetch target page with 5s timeout and 1MB size limit
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const response = await fetch(parsedUrl.href, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; MULTIFLY-AI-Checker/1.0; +https://multifly.in)',
        'Accept': 'text/html,application/xhtml+xml'
      }
    });

    clearTimeout(timeout);

    if (!response.ok) {
      return res.status(400).json({ error: `Target server responded with HTTP status ${response.status}.` });
    }

    // Stream with 1MB limit
    const reader = response.body.getReader();
    let receivedBytes = 0;
    const chunks = [];
    const MAX_BYTES = 1024 * 1024; // 1MB

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      receivedBytes += value.length;
      if (receivedBytes > MAX_BYTES) {
        reader.cancel();
        break;
      }
      chunks.push(value);
    }

    const htmlBuffer = Buffer.concat(chunks);
    const html = htmlBuffer.toString('utf-8');

    // Checklist Analysis
    const hasSchemaJsonLd = /<script[^>]*type=["']application\/ld\+json["'][^>]*>[\s\S]*?<\/script>/i.test(html);
    const hasMicrodata = /itemscope|itemtype/i.test(html);
    const hasStructuredData = hasSchemaJsonLd || hasMicrodata;

    const hasH1 = /<h1[^>]*>[\s\S]*?<\/h1>/i.test(html);
    const hasHeadings = /<h[1-3][^>]*>/i.test(html);
    const hasServiceKeywords = /service|solution|product|about/i.test(html);
    const clearServices = hasH1 && (hasHeadings || hasServiceKeywords);

    const hasTelLink = /href=["']tel:[^"']+["']/i.test(html);
    const hasMailto = /href=["']mailto:[^"']+["']/i.test(html);
    const hasPhonePattern = /(?:\+91|91|0)?[6-9]\d{9}|(?:\+1)?\s?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}/.test(html);
    const hasContactDetails = hasTelLink || hasMailto || hasPhonePattern;

    const hasFaqTag = /<details[\s\S]*?<\/details>/i.test(html);
    const hasFaqKeyword = /faq|frequently asked|questions/i.test(html);
    const hasFaqSchema = /"FAQPage"/i.test(html);
    const hasFaq = hasFaqTag || hasFaqKeyword || hasFaqSchema;

    const hasViewport = /<meta[^>]*name=["']viewport["'][^>]*>/i.test(html);

    const hasLazyImages = /loading=["']lazy["']/i.test(html);
    const reasonableSize = receivedBytes < 500 * 1024;
    const pageSpeedHints = hasLazyImages || reasonableSize;

    // Calculate score
    let score = 0;
    const checklist = [];
    const tips = [];

    if (hasStructuredData) {
      score += 25;
      checklist.push({ label: 'Structured Schema.org Data', status: 'pass', detail: 'Found Schema JSON-LD / microdata tags.' });
    } else {
      checklist.push({ label: 'Structured Schema.org Data', status: 'fail', detail: 'Missing JSON-LD schema needed by LLMs to cite services.' });
      tips.push('Add Schema.org Organization and Service markup so ChatGPT and Perplexity can index verified facts.');
    }

    if (clearServices) {
      score += 20;
      checklist.push({ label: 'Clear Semantic Headings & Services', status: 'pass', detail: 'H1 and clear service hierarchy detected.' });
    } else {
      checklist.push({ label: 'Clear Semantic Headings & Services', status: 'fail', detail: 'Missing clear H1 or service sections.' });
      tips.push('Organize pages with explicit H1/H2 tags describing your niche services so search AI extracts capabilities.');
    }

    if (hasContactDetails) {
      score += 20;
      checklist.push({ label: 'Direct Verified Contact Endpoints', status: 'pass', detail: 'Phone/email link detected on page.' });
    } else {
      checklist.push({ label: 'Direct Verified Contact Endpoints', status: 'fail', detail: 'No direct tel: or mailto: links found.' });
      tips.push('Include clickable telephone (tel:) and email endpoints to improve entity trust in knowledge graphs.');
    }

    if (hasFaq) {
      score += 15;
      checklist.push({ label: 'FAQ & Question-Answering Content', status: 'pass', detail: 'FAQ or Q&A patterns detected.' });
    } else {
      checklist.push({ label: 'FAQ & Question-Answering Content', status: 'fail', detail: 'No FAQ or Q&A section detected.' });
      tips.push('Add an FAQ accordion answering pricing, timelines, and deliverables to trigger direct AI answer cards.');
    }

    if (hasViewport) {
      score += 10;
      checklist.push({ label: 'Mobile Responsive Viewport', status: 'pass', detail: 'Meta viewport configured properly.' });
    } else {
      checklist.push({ label: 'Mobile Responsive Viewport', status: 'fail', detail: 'Missing viewport meta tag.' });
      tips.push('Add viewport meta configuration for modern mobile responsiveness.');
    }

    if (pageSpeedHints) {
      score += 10;
      checklist.push({ label: 'Page Speed & Weight Signals', status: 'pass', detail: 'Good initial payload size and image optimization.' });
    } else {
      checklist.push({ label: 'Page Speed & Weight Signals', status: 'fail', detail: 'Page HTML or payload could be lighter.' });
      tips.push('Optimize DOM weight and enable lazy loading on below-the-fold media.');
    }

    // Save lead record of checker run
    save('leads.jsonl', {
      type: 'visibility-check',
      businessName,
      url: parsedUrl.href,
      niche,
      score,
      phone: clean(req.body.phone, 15) || null
    });

    res.json({
      ok: true,
      score,
      checklist,
      tips,
      domain: parsedUrl.hostname,
      disclaimer: 'Basic checklist, not a guarantee of AI rankings.'
    });
  } catch (err) {
    console.error('Visibility check error:', err.message);
    res.status(502).json({ error: 'Could not fetch or analyze URL. Please ensure the website is online and accessible.' });
  }
});

// PHASE 9: Blog / Insights Routes & RSS Feed
const blog = require('./lib/blog');
app.get('/blog', (_req, res) => res.redirect(301, '/blog.html'));
app.get('/pricing', (_req, res) => res.redirect(301, '/pricing.html'));

// Common Page Header Template
function renderNavHeader() {
  return `
<header class="site-header" id="siteHeader">
  <div class="wrap nav-container">
    <a class="brand-logo" href="/index.html" aria-label="MULTIFLY Home">
      <span class="brand-icon">
        <svg width="32" height="32" viewBox="0 0 36 36" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <defs>
            <linearGradient id="mfGradNav1" x1="2" y1="4" x2="34" y2="32" gradientUnits="userSpaceOnUse">
              <stop stop-color="#3B5BFC"/><stop offset="0.65" stop-color="#6366F1"/><stop offset="1" stop-color="#FF9D1C"/>
            </linearGradient>
            <linearGradient id="mfGradNav2" x1="8" y1="26" x2="32" y2="8" gradientUnits="userSpaceOnUse">
              <stop stop-color="#FF9D1C"/><stop offset="1" stop-color="#3B5BFC"/>
            </linearGradient>
          </defs>
          <rect width="36" height="36" rx="10" fill="currentColor" fill-opacity="0.08"/>
          <path d="M7 27V12L14 20L18 15L22 20L29 12V27" stroke="url(#mfGradNav1)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
          <path d="M12 24L18 17L24 24" stroke="url(#mfGradNav2)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
          <circle cx="18" cy="10" r="2.2" fill="#FF9D1C"/>
        </svg>
      </span>
      <span class="logo-text">MULTIFLY</span>
      <span class="logo-tag">MSME</span>
    </a>
    <nav class="desktop-nav" aria-label="Main Navigation">
      <div class="nav-item"><a href="/about.html" class="nav-trigger">About</a></div>
      <div class="nav-item"><a href="/services.html" class="nav-trigger">Services</a></div>
      <div class="nav-item"><a href="/portfolio.html" class="nav-trigger">Portfolio</a></div>
      <div class="nav-item"><a href="/blog.html" class="nav-trigger">Blog</a></div>
      <div class="nav-item"><a href="/pricing.html" class="nav-trigger">Pricing</a></div>
      <div class="nav-item"><a href="/contact.html" class="nav-trigger">Contact</a></div>
    </nav>
    <div class="nav-actions">
      <button class="theme-toggle-btn" id="themeToggle" aria-label="Toggle theme">
        <svg class="icon-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
        <svg class="icon-moon" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
      </button>
      <a href="/login.html" class="btn btn-ghost btn-sm btn-login">Log In</a>
      <a href="/contact.html" class="btn btn-primary btn-sm">Contact Us</a>
    </div>
  </div>
</header>`;
}

function renderFooter() {
  return `
<footer>
  <div class="wrap" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px;">
    <span>© 2026 MULTIFLY. Founder: Ayush Mishra (86578 77578). All prices in Indian rupees.</span>
    <div>
      <a href="/about.html" style="margin-right:16px;">About</a>
      <a href="/services.html" style="margin-right:16px;">Services</a>
      <a href="/portfolio.html" style="margin-right:16px;">Portfolio</a>
      <a href="/blog.html" style="margin-right:16px;">Research Blog</a>
      <a href="/rss.xml" style="margin-right:16px;">RSS Feed</a>
      <a href="/pricing.html" style="margin-right:16px;">Pricing</a>
      <a href="/contact.html">Contact</a>
    </div>
  </div>
</footer>
<script src="/js/script.js" defer></script>
<script src="/js/nav.js" defer></script>`;
}

// RSS Feed
app.get('/rss.xml', (req, res) => {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const baseUrl = `${protocol}://${req.get('host')}`;
  res.set('Content-Type', 'application/xml; charset=utf-8');
  res.send(blog.generateRssXml(baseUrl));
});

// JSON API endpoint for posts
app.get('/api/posts', (_req, res) => {
  res.json(blog.getAllPosts());
});

// Blog List Page
app.get('/blog', (req, res) => {
  const posts = blog.getAllPosts();
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const canonicalUrl = `${protocol}://${req.get('host')}/blog`;

  const cardsHtml = posts.map(p => `
    <a href="/blog/${p.slug}" class="blog-card">
      <div class="blog-meta-top">
        <span class="blog-category-tag">${p.category}</span>
        <span>${p.readingTime}</span>
      </div>
      <h3 class="blog-card-title">${p.title}</h3>
      <p class="blog-card-excerpt">${p.description}</p>
      <div class="blog-card-footer">
        <span>${p.date} · By ${p.author}</span>
        <span class="read-more-link">Read article &rarr;</span>
      </div>
    </a>
  `).join('');

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Research &amp; Insights | MULTIFLY - AEO &amp; AI Visibility for MSMEs</title>
<meta name="description" content="Read actionable research on Answer Engine Optimisation (AEO), Schema entity graphs, and digital growth strategies for Indian MSMEs.">
<link rel="canonical" href="${canonicalUrl}">
<meta property="og:title" content="Research &amp; Insights | MULTIFLY">
<meta property="og:description" content="Actionable research on Answer Engine Optimisation (AEO) and AI visibility for MSMEs.">
<meta property="og:url" content="${canonicalUrl}">
<meta property="og:type" content="website">
<link rel="icon" href="/images/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/css/style.css">
</head>
<body>
${renderNavHeader()}
<main style="padding-top: calc(var(--nav-height) + 40px); min-height: 80vh;">
  <div class="wrap">
    <div class="section-head" style="max-width: 800px;">
      <span class="section-tag">Research &amp; Guides</span>
      <h1 class="section-title">AEO &amp; AI Search Visibility for MSMEs</h1>
      <p class="section-lead">
        Original insights on how Answer Engine Optimisation, structured Schema entities, and targeted ad setups help Indian small businesses get cited and recommended by AI.
      </p>
    </div>
    <div class="blog-grid">
      ${cardsHtml}
    </div>
  </div>
</main>
${renderFooter()}
</body>
</html>`);
});

// Single Blog Post Page
app.get('/blog/:slug', (req, res) => {
  const post = blog.getPostBySlug(req.params.slug);
  if (!post) {
    return res.status(404).send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Article Not Found | MULTIFLY</title><link rel="stylesheet" href="/css/main.css"></head>
<body style="text-align:center; padding:100px 20px;">
  <h2>Article Not Found</h2>
  <p style="margin: 16px 0;"><a href="/blog.html" class="btn btn-primary">Back to Research</a></p>
</body></html>`);
  }

  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const postUrl = `${protocol}://${req.get('host')}/blog/${post.slug}`;
  const encodedUrl = encodeURIComponent(postUrl);
  const encodedTitle = encodeURIComponent(post.title);

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${post.title} | MULTIFLY Research</title>
<meta name="description" content="${post.description}">
<link rel="canonical" href="${postUrl}">
<meta property="og:title" content="${post.title}">
<meta property="og:description" content="${post.description}">
<meta property="og:url" content="${postUrl}">
<meta property="og:type" content="article">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${post.title}">
<meta name="twitter:description" content="${post.description}">
<link rel="icon" href="/images/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/css/style.css">
<!-- Article Schema JSON-LD -->
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "BlogPosting",
  "headline": "${post.title}",
  "description": "${post.description}",
  "author": {
    "@type": "Person",
    "name": "${post.author}"
  },
  "publisher": {
    "@type": "Organization",
    "name": "MULTIFLY",
    "url": "${protocol}://${req.get('host')}"
  },
  "datePublished": "${post.date}",
  "mainEntityOfPage": "${postUrl}"
}
</script>
</head>
<body>
${renderNavHeader()}
<article>
  <header class="article-page-header">
    <div class="wrap">
      <nav class="article-breadcrumbs" aria-label="Breadcrumbs">
        <a href="/index.html">Home</a> &rsaquo; <a href="/blog.html">Research</a> &rsaquo; <span>${post.category}</span>
      </nav>
      <h1 class="article-title">${post.title}</h1>
      <div class="article-meta-bar">
        <span>By <strong>${post.author}</strong></span>
        <span>•</span>
        <span>Published ${post.date}</span>
        <span>•</span>
        <span>${post.readingTime}</span>
        <span>•</span>
        <span class="badge-pill">${post.category}</span>
      </div>
    </div>
  </header>

  <div class="article-container">
    <div class="article-prose">
      ${post.htmlContent}
    </div>

    <!-- Social Share Bar -->
    <div class="article-share-bar">
      <span style="font-weight:700; font-size:0.92rem;">Share this research:</span>
      <div class="share-buttons">
        <a href="https://wa.me/?text=${encodedTitle}%20${encodedUrl}" target="_blank" rel="noopener" class="share-btn">
          <span>WhatsApp</span>
        </a>
        <a href="https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}" target="_blank" rel="noopener" class="share-btn">
          <span>LinkedIn</span>
        </a>
        <a href="https://twitter.com/intent/tweet?text=${encodedTitle}&url=${encodedUrl}" target="_blank" rel="noopener" class="share-btn">
          <span>X / Twitter</span>
        </a>
      </div>
    </div>

    <!-- Bottom Consultation CTA -->
    <div style="margin-top:48px; background:var(--bg-card); border:1px solid var(--border-subtle); border-radius:var(--radius-lg); padding:32px; text-align:center;">
      <h3 style="font-size:1.3rem; margin-bottom:8px;">Ready to structure your business for AI search?</h3>
      <p style="color:var(--text-muted); font-size:0.95rem; margin-bottom:20px; max-width:50ch; margin-left:auto; margin-right:auto;">
        Book a free discovery call with founder Ayush Mishra. We will audit your current visibility and provide a fixed quote in writing.
      </p>
      <a href="/contact.html" class="btn btn-primary">Book Free Consultation</a>
    </div>
  </div>
</article>
${renderFooter()}
</body>
</html>`);
});

// PHASE 10: Dedicated Pricing Page (/pricing)
app.get('/pricing', (req, res) => {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const pageUrl = `${protocol}://${req.get('host')}/pricing`;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pricing &amp; Plans | MULTIFLY - Clear Pricing in Indian Rupees</title>
<meta name="description" content="Transparent, fixed pricing for AEO websites (₹15,000 to ₹30,000), social media management (₹5,000/mo), Meta and ChatGPT ads setup (₹5,000), and custom apps.">
<link rel="canonical" href="${pageUrl}">
<meta property="og:title" content="Pricing &amp; Plans | MULTIFLY">
<meta property="og:description" content="Transparent fixed pricing in Indian rupees for websites, ads, and automation. Pay securely online via Razorpay.">
<meta property="og:url" content="${pageUrl}">
<meta property="og:type" content="website">
<link rel="icon" href="/images/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/css/style.css">
<style>
dialog{border:1px solid var(--border-subtle);border-radius:18px;background:var(--bg-page);color:var(--text-main);padding:26px;width:min(440px,92vw)}
dialog::backdrop{background:rgba(10,12,30,.6)}
.msg{min-height:1.4em;font-size:.92rem;margin-top:8px}
.msg.err{color:#d6336c}.msg.ok{color:#1c9a57}
</style>
</head>
<body>
${renderNavHeader()}

<main>
  <!-- Pricing Header & Toggle -->
  <header class="pricing-page-hero">
    <div class="wrap">
      <span class="section-tag">Transparent Pricing</span>
      <h1 class="section-title">Clear Pricing. Zero Surprises.</h1>
      <p class="section-lead" style="max-width: 65ch; margin: 0 auto;">
        All prices in Indian rupees. Scope confirmed in writing before work begins. Pay securely online for fixed-price plans, or request a quote for custom development.
      </p>

      <!-- Monthly vs One-Time Toggle -->
      <div class="pricing-toggle-wrap" role="group" aria-label="Filter Plans">
        <button class="pricing-toggle-btn active" data-filter="all">All Plans</button>
        <button class="pricing-toggle-btn" data-filter="one-time">One-Time Setups</button>
        <button class="pricing-toggle-btn" data-filter="monthly">Monthly Retainers</button>
      </div>
    </div>
  </header>

  <div class="wrap">
    <!-- Comparison Grid -->
    <div class="pricing-grid-compare" id="pricingGrid">
      <!-- Plan 1: AEO Website Starter -->
      <div class="plan-card featured-plan" data-type="one-time">
        <span class="featured-ribbon">Most Popular</span>
        <span class="plan-type-pill">One-Time Setup</span>
        <h3 class="plan-title">AEO Website</h3>
        <div class="plan-price-row">
          <span class="plan-amount">₹15,000</span>
          <span class="plan-period">/ starting price</span>
        </div>
        <p class="plan-summary">
          Engineered for focused small-business websites. Competitive niches and larger catalogs go up to ₹30,000, confirmed in your written quote.
        </p>

        <div class="plan-included-title">What is included:</div>
        <ul class="plan-included-list">
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Custom mobile-first website architecture</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Schema.org JSON-LD structured data for AI engines</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Niche competitor research &amp; entity mapping</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>On-page SEO foundations &amp; fast static speed</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Lead form integration &amp; domain launch setup</span>
          </li>
        </ul>

        <button class="btn btn-primary" data-buy="website" data-name="AEO website, starter" data-amt="₹15,000">Pay and start</button>
      </div>

      <!-- Plan 2: Social Media Management -->
      <div class="plan-card" data-type="monthly">
        <span class="plan-type-pill">Monthly Retainer</span>
        <h3 class="plan-title">Social Media</h3>
        <div class="plan-price-row">
          <span class="plan-amount">₹5,000</span>
          <span class="plan-period">/ month</span>
        </div>
        <p class="plan-summary">
          Consistent, high-quality digital presence across LinkedIn, Instagram, and Facebook with direct group distribution.
        </p>

        <div class="plan-included-title">What is included:</div>
        <ul class="plan-included-list">
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Designed posts, infographics &amp; carousels</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Multi-platform scheduling &amp; content calendar</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Targeted group posting on your behalf</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Monthly reach report &amp; audience check-in</span>
          </li>
        </ul>

        <button class="btn btn-ghost" data-buy="social" data-name="Social media management, first month" data-amt="₹5,000">Pay first month</button>
      </div>

      <!-- Plan 3: Meta Ads Setup -->
      <div class="plan-card" data-type="one-time">
        <span class="plan-type-pill">One-Time Setup</span>
        <h3 class="plan-title">Meta Ads Setup</h3>
        <div class="plan-price-row">
          <span class="plan-amount">₹5,000</span>
          <span class="plan-period">/ one-time setup</span>
        </div>
        <p class="plan-summary">
          Complete Facebook and Instagram advertising campaign built for your exact market and audience.
        </p>

        <div class="plan-included-title">What is included:</div>
        <ul class="plan-included-list">
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Niche-specific audience targeting &amp; lookalikes</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Conversion tracking &amp; Meta Pixel configuration</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>High-intent ad copy &amp; creative guidelines</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Direct billing to your card (zero agency markup)</span>
          </li>
        </ul>

        <button class="btn btn-ghost" data-buy="meta" data-name="Meta ads setup" data-amt="₹5,000">Pay and start</button>
      </div>

      <!-- Plan 4: ChatGPT Ads Setup -->
      <div class="plan-card" data-type="one-time">
        <span class="plan-type-pill">One-Time Setup</span>
        <h3 class="plan-title">ChatGPT Ads Setup</h3>
        <div class="plan-price-row">
          <span class="plan-amount">₹5,000</span>
          <span class="plan-period">/ one-time setup</span>
        </div>
        <p class="plan-summary">
          Target potential buyers searching inside conversational AI engines and modern discovery networks.
        </p>

        <div class="plan-included-title">What is included:</div>
        <ul class="plan-included-list">
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Account, audience and prompt keyword structure</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>High-intent B2B search campaign architecture</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Conversion tracking &amp; goal setup</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Ad spend paid directly to platform</span>
          </li>
        </ul>

        <button class="btn btn-ghost" data-buy="chatgpt" data-name="ChatGPT ads setup" data-amt="₹5,000">Pay and start</button>
      </div>

      <!-- Plan 5: Apps & Automation -->
      <div class="plan-card" data-type="all">
        <span class="plan-type-pill">Custom Scope</span>
        <h3 class="plan-title">Apps &amp; Automation</h3>
        <div class="plan-price-row">
          <span class="plan-amount">Custom</span>
          <span class="plan-period">/ binding quote</span>
        </div>
        <p class="plan-summary">
          Custom Android/iOS apps, admin dashboards, and WhatsApp/LinkedIn automation workflows.
        </p>

        <div class="plan-included-title">What is included:</div>
        <ul class="plan-included-list">
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Custom mobile &amp; responsive web app development</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Intuitive admin dashboard for business operations</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>WhatsApp &amp; LinkedIn automation (no per-message fee)</span>
          </li>
          <li class="plan-included-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
            <span>Built in milestones with your review &amp; post-launch support</span>
          </li>
        </ul>

        <a href="/contact.html" class="btn btn-ghost">Request Discovery Call</a>
      </div>
    </div>

    <!-- Ad Spend Callout Banner -->
    <div class="ad-spend-banner">
      <div class="banner-shield-icon">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
      </div>
      <div>
        <h4 style="font-size:1.05rem; font-weight:700; margin-bottom:4px;">Direct Platform Ad Spend Protection</h4>
        <p style="font-size:0.88rem; color:var(--text-muted); margin:0;">
          All media ad spend is paid directly to platforms (Meta, OpenAI) through your card. MULTIFLY charges strictly the fixed setup fee, with zero percentage cut on your ad spend. Payments are processed securely via Razorpay.
        </p>
      </div>
    </div>

    <!-- Pricing FAQ -->
    <section class="faq-section" style="border:none; padding: 48px 0;">
      <div class="section-head" style="text-align:center; max-width:700px; margin:0 auto 32px;">
        <h2 class="section-title">Pricing FAQ</h2>
        <p class="section-lead">Common questions regarding payments, invoices, timelines, and scope.</p>
      </div>
      <div class="faq-accordion-container">
        <div class="faq-card">
          <button class="faq-trigger" aria-expanded="false">
            <span>Can I pay online securely right now?</span>
            <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M6 9l6 6 6-6"/></svg>
          </button>
          <div class="faq-answer">
            <p>Yes. All fixed-price plans (AEO Website ₹15,000, Social Media ₹5,000, Meta Ads ₹5,000, ChatGPT Ads ₹5,000) can be paid immediately using UPI, debit/credit cards, netbanking, or wallets via Razorpay.</p>
          </div>
        </div>
        <div class="faq-card">
          <button class="faq-trigger" aria-expanded="false">
            <span>What happens if my website needs more than ₹15,000?</span>
            <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M6 9l6 6 6-6"/></svg>
          </button>
          <div class="faq-answer">
            <p>The ₹15,000 tier covers focused small business websites. Highly competitive niches or extensive catalogs go up to ₹30,000. We confirm the exact scope and binding quote in writing before you pay anything.</p>
          </div>
        </div>
        <div class="faq-card">
          <button class="faq-trigger" aria-expanded="false">
            <span>How does the monthly social media plan work?</span>
            <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M6 9l6 6 6-6"/></svg>
          </button>
          <div class="faq-answer">
            <p>You pay the first month (₹5,000) online to start. Our team prepares and schedules your monthly calendar. You can cancel at the end of any monthly cycle with no long-term lock-in.</p>
          </div>
        </div>
        <div class="faq-card">
          <button class="faq-trigger" aria-expanded="false">
            <span>Do I receive a GST invoice?</span>
            <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M6 9l6 6 6-6"/></svg>
          </button>
          <div class="faq-answer">
            <p>Yes, an invoice with complete payment details and GST registration placeholders is generated for your records.</p>
          </div>
        </div>
      </div>
    </section>
  </div>
</main>

${renderFooter()}

<script>
// Filter toggle
const toggleBtns = document.querySelectorAll('.pricing-toggle-btn');
const cards = document.querySelectorAll('.plan-card');

toggleBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    toggleBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const filter = btn.getAttribute('data-filter');

    cards.forEach(card => {
      const type = card.getAttribute('data-type');
      if (filter === 'all' || type === filter || type === 'all') {
        card.style.display = 'flex';
      } else {
        card.style.display = 'none';
      }
    });
  });
});

// FAQ Accordion
document.querySelectorAll('.faq-card').forEach(card => {
  card.querySelector('.faq-trigger')?.addEventListener('click', () => {
    const isOpen = card.classList.contains('open');
    document.querySelectorAll('.faq-card').forEach(c => c.classList.remove('open'));
    if (!isOpen) card.classList.add('open');
  });
});

// Checkout prices and payment state are handled by the shared server-backed checkout.
document.querySelectorAll('[data-buy]').forEach(b => {
  b.addEventListener('click', () => {
    window.location.assign('/checkout?service=' + encodeURIComponent(b.dataset.buy));
  });
});
</script>
</body>
</html>`);
});

const PORT = Number(process.env.PORT) || 3000;
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API route not found.' });
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.listen(PORT, () => {
  console.log('MULTIFLY running on http://localhost:' + PORT);
  if (!hasValidRazorpayKeys(process.env)) {
    console.log('Razorpay keys missing, payments disabled');
  } else if (process.env.RAZORPAY_KEY_ID.startsWith('rzp_test_')) {
    console.log('Razorpay ready (test mode)');
  } else {
    console.log('Razorpay ready (live mode)');
  }
});
