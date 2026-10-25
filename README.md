# MULTIFLY website

Node.js + Express website for MULTIFLY. Static pages and local SVG artwork are served from `public/`; contacts are appended to `data/leads.jsonl`, while checkout records are stored in `data/payments.sqlite`.

## Run locally

1. Install Node.js (LTS).
2. In this project folder run `npm install`.
3. Copy `.env.example` to `.env`. Add Razorpay **test** keys, a webhook secret, and the payment fallback details you want customers to see.
4. Run `npm start` and open `http://localhost:3000`.
5. Run the payment integration tests with `npm test`.

The app reports whether Razorpay is disabled, in test mode, or in live mode at startup. If keys are absent, checkout displays configured UPI/bank transfer instructions and a WhatsApp confirmation link instead of a non-working payment button.

## Website pages

The public site is organized into static HTML pages in `public/`: `index.html`, `about.html`, `services.html`, individual `service-*.html` detail pages, `portfolio.html`, `blog.html`, `pricing.html`, and `contact.html`. The legal pages (`privacy.html`, `terms.html`, and `refund-policy.html`) are drafts and need lawyer review. Shared page styles and navigation are in `public/css/style.css` and `public/js/script.js`. Unknown HTML routes receive the custom 404 page.

## Search and AI discovery

- Public pages use page-specific titles and descriptions, absolute canonical URLs, Open Graph/Twitter metadata, and structured data for the organization, founder, breadcrumbs, service pages, and visible FAQs.
- `public/robots.txt` and `public/sitemap.xml` expose the indexable site pages. Login, account, checkout, payment, subscription-management, and 404 pages are excluded or marked `noindex`.
- MULTIFLY's stated service area is India. No office address or map coordinates are published because none have been provided; add verified location details before using local-business markup or targeting a specific city.
- Canonical and share URLs currently use `https://multifly.in`. Change the site origin consistently in `public/js/script.js`, `public/robots.txt`, `public/sitemap.xml`, and the homepage social metadata if production uses a different domain.
- Search rankings and AI citations cannot be guaranteed. Structured content helps systems understand the information but does not control third-party results.

## Payments and checkout

- `/checkout.html` provides service selection, customer details, server-calculated GST/discount, consent links, Razorpay checkout and transfer fallback.
- Set `GST_PERCENT` for the tax rate. Optional coupons are configured only by `COUPON_CODE` and `COUPON_DISCOUNT_PERCENT`.
- Razorpay order and payment status, webhook events, and subscription status are stored in SQLite under `data/payments.sqlite`.
- Configure `RAZORPAY_WEBHOOK_SECRET` in the Razorpay dashboard for the `/api/razorpay/webhook` endpoint.
- SMTP variables enable invoice PDFs to be sent to the customer and `OWNER_EMAIL`.
- Social Media Management supports a monthly Razorpay subscription; the successful receipt links to the secure cancel page.
- The legal pages `/terms.html`, `/privacy.html`, and `/refund-policy.html` are draft text and must be reviewed by a lawyer before launch.

See [TESTING.md](./TESTING.md) for the test-mode payment flow. Do not use live keys until your webhook, SMTP, policies, prices, and bank details have been reviewed.

## Accounts

Customers can create an account or log in at `/login.html`. Configure both `ADMIN_EMAIL` and a unique `ADMIN_PASSWORD` (minimum 12 characters) before first startup to seed an administrator account. No default administrator password is created for new databases.

## Deployment notes

Deploy to a Node.js host such as Render, Railway, or a VPS; GitHub Pages cannot run the Express API. Set the environment variables in the host's secret manager and use HTTPS in production. Back up `data/payments.sqlite` and `data/leads.jsonl` securely.
