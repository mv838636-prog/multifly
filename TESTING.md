# MULTIFLY payment test flow

Use Razorpay **test mode only**. Set `RAZORPAY_KEY_ID=rzp_test_...`, `RAZORPAY_KEY_SECRET`, and a webhook secret in `.env`, then run `npm start`. The checkout shows a Test mode banner when the public key has the `rzp_test_` prefix.

## Razorpay test instruments

- Test card: Visa `4111 1111 1111 1111`; use any future expiry date, any 3-digit CVV, and a test cardholder name.
- Test UPI success ID: `success@razorpay`.
- Test UPI failure ID: `failure@razorpay`.
- These are sandbox-only instruments. Do not use real card or bank details.

## Browser test steps

1. Open `http://localhost:3000/checkout`.
2. Choose a service and continue.
3. Enter test customer details, proceed to review, confirm the server-returned GST/total, and accept all three policy links.
4. Pay with the test card or `success@razorpay`; verify the receipt page shows order/payment IDs, subtotal, GST and total.
5. Repeat with `failure@razorpay` or dismiss Razorpay; confirm the UI reports failure/cancellation and the order is not marked paid.
6. Use the Razorpay Dashboard webhook test tool to deliver a signed `payment.captured` event twice; only one event/payment record should be applied. Also test `payment.failed` and `refund.processed`.
7. Verify an invoice email is sent after configuring SMTP settings.

## Automated checks

Run `npm test`. The tests use a fake local Razorpay client and temporary SQLite databases (no real payment API calls) to check the server quote, valid signature, wrong signature, altered gateway amount, and duplicate signed webhook handling.
