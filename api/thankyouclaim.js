// api/thankyouclaim.js — CommonJS serverless function (Vercel root /api/*)
const SHOPIFY_SHOP = process.env.SHOPIFY_SHOP;                 // e.g. charmsforchange.myshopify.com
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;   // shpat_...
const API_VERSION = '2025-07';                                 // bump to current

function genCode(prefix = 'TY') {
  const slug = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `${prefix}-${slug}`;
}

module.exports = async (req, res) => {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Body may arrive as string or object depending on runtime
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const { expiresAt } = body;

    const startsAt = new Date();
    const endsAt = expiresAt ? new Date(expiresAt) : new Date(startsAt.getTime() + 48 * 60 * 60 * 1000);

    // Generate code with TY prefix
    const code = genCode('TY');

    // GraphQL mutation (uses SINGLE "code", not "codes")
    const mutation = `
      mutation discountCodeBasicCreate($basicCodeDiscount: DiscountCodeBasicInput!) {
        discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
          codeDiscountNode { id }
          userErrors { field message }
        }
      }
    `;

    // Read percent from env (e.g., TY_PERCENT="20") → decimal 0.20
    const pct = Math.min(
      1,
      Math.max(0, (parseFloat(process.env.TY_PERCENT || '20') || 20) / 100)
    );

    const variables = {
      basicCodeDiscount: {
        title: `Thank You ${code}`,
        startsAt: startsAt.toISOString(),
        endsAt: endsAt.toISOString(),

        // Required on newer API versions
        customerSelection: { all: true },

        // What the customer gets
        customerGets: {
          value: { percentage: pct },   // decimal 0–1
          items: { all: true }
        },

        // Stacking + usage
        combinesWith: { orderDiscounts: true, productDiscounts: false, shippingDiscounts: false },
        usageLimit: 1,
        appliesOncePerCustomer: true,

        // SINGLE code field
        code
      }
    };

    const r = await fetch(`https://${SHOPIFY_SHOP}/admin/api/${API_VERSION}/graphql.json`, {
      method: 'POST',
      headers: {
        'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ query: mutation, variables })
    });

    const data = await r.json().catch(() => ({}));

    // Top-level GraphQL errors
    if (data?.errors?.length) {
      console.error('GraphQL errors', data.errors);
      return res.status(400).json({ error: 'GraphQL error', errors: data.errors });
    }

    if (!r.ok) {
      console.error('Shopify HTTP error', r.status, data);
      return res.status(502).json({ error: 'Shopify HTTP error', status: r.status, details: data });
    }

    const errs = data?.data?.discountCodeBasicCreate?.userErrors;
    if (errs?.length) {
      console.error('Shopify validation errors', errs);
      return res.status(400).json({ error: 'Shopify validation error', userErrors: errs });
    }

    const node = data?.data?.discountCodeBasicCreate?.codeDiscountNode;
    if (!node) {
      console.error('No codeDiscountNode in response', data);
      return res.status(500).json({ error: 'No codeDiscountNode returned' });
    }

    return res.status(200).json({
      ok: true,
      code,
      startsAt: startsAt.toISOString(),
      endsAt: endsAt.toISOString(),
      nodeId: node.id
    });
  } catch (e) {
    console.error('Unhandled error creating discount', e);
    return res.status(500).json({ error: 'Unhandled error', message: e?.message || String(e) });
  }
};
