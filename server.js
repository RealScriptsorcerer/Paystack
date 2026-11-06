require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();

// Standard middleware
app.use(express.static(path.join(__dirname, 'public')));

// Parse JSON while keeping raw body buffer for secure webhook verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

// Kenyan prefix regex matching
const SAFARICOM_REGEX = /^(?:\+?254|0)?(7(?:0[0-8]|1[0-9]|2[0-9]|4[0-3568]|5[789]|6[89]|9[0-9])|1(?:1[0-5]))\d{6}$/;
const AIRTEL_REGEX = /^(?:\+?254|0)?(7(?:3[0-9]|5[0-6]|8[0-9])|1(?:0[0-2]|1[6-9]))\d{6}$/;

function detectProvider(phone) {
  const cleaned = phone.replace(/\s+/g, '');
  if (SAFARICOM_REGEX.test(cleaned)) return 'mpesa';
  if (AIRTEL_REGEX.test(cleaned)) return 'airtel';
  return null;
}

function normalizeKenyanPhone(phone) {
  let cleaned = phone.replace(/[^0-9+]/g, '').trim();
  if (cleaned.startsWith('+254')) return cleaned;
  if (cleaned.startsWith('254')) return `+${cleaned}`;
  if (cleaned.startsWith('0')) return `+254${cleaned.slice(1)}`;
  return `+254${cleaned}`;
}

// 1. Trigger STK push / Mobile Money prompt
app.post('/api/charge', async (req, res) => {
  const { phone, amount } = req.body;

  if (!phone || !amount || Number(amount) < 1) {
    return res.status(400).json({ error: 'Valid phone and amount are required' });
  }

  const provider = detectProvider(phone);
  if (!provider) {
    return res.status(400).json({
      error: 'Unrecognized network prefix. Provide a valid Safaricom or Airtel number.'
    });
  }

  const formattedPhone = normalizeKenyanPhone(phone);
  const amountInCents = Math.round(Number(amount) * 100);

  const payload = {
    email: `${formattedPhone.replace('+', '')}@mobilemoney.local`,
    amount: amountInCents,
    currency: 'KES',
    mobile_money: {
      phone: formattedPhone,
      provider: provider // 'mpesa' or 'airtel'
    }
  };

  try {
    const paystackRes = await fetch('https://api.paystack.co/charge', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const data = await paystackRes.json();
    return res.status(paystackRes.status).json({ ...data, provider });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// 2. Poll transaction status directly from Paystack
app.get('/api/verify/:reference', async (req, res) => {
  const { reference } = req.params;

  try {
    const paystackRes = await fetch(`https://api.paystack.co/charge/${encodeURIComponent(reference)}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`
      }
    });

    const data = await paystackRes.json();
    return res.status(paystackRes.status).json(data);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// 3. Webhook listener for asynchronous confirmation
app.post('/api/webhook', (req, res) => {
  const signature = req.headers['x-paystack-signature'];
  const hash = crypto
    .createHmac('sha512', PAYSTACK_SECRET_KEY)
    .update(req.rawBody)
    .digest('hex');

  if (hash !== signature) {
    return res.status(401).send('Invalid signature');
  }

  const event = req.body;
  if (event.event === 'charge.success') {
    const data = event.data;
    console.log(`[PAID] Ref: ${data.reference} | Phone: ${data.authorization?.mobile_money_number || data.customer?.phone} | Amount: KES ${data.amount / 100}`);
  }

  return res.sendStatus(200);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Gateway active on http://localhost:${PORT}`));
        
