// /pages/api/thankyouclaim.ts (or /app/api/thankyouclaim/route.ts with minor tweaks)
import type { NextApiRequest, NextApiResponse } from 'next';

const SHOPIFY_SHOP = process.env.SHOPIFY_SHOP as string;          // "your-store.myshopify.com"
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN as string; // Admin API access token
const API_VERSION = '2024-04'; // or your pinned version

function genCode(prefix = 'THANKYOU') {
  const slug = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `${prefix}-${slug}`;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    return res.status(204).end();
  }

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    res.setHeader('Access-Control-Allow-Origin', '*');

    // If the client passes an expiresAt (ISO), use it; otherwise 48h from now
    const { expiresAt } = req.body || {};
    const startsAt = new Date();
    const endsAt = expiresAt ? new Date(expiresAt) : new Date(startsAt.getTime() + 48 * 60 * 60 * 1000);

    const code = genCode('THANKYOU');

    const mutation = `
      mutation discountCodeBasicCreate($basicCodeDiscount: DiscountCodeBasicInput!) {
        discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
          codeDiscountNode {
            id
            codeDiscount {
              ... on DiscountCodeBasic {
                title
                codes(first: 1) { nodes { code } }
                status
                startsAt
                endsAt
              }
            }
          }
          userErrors { field message }
        }
      }
    `;

    // EXAMPLE: 10% off; tweak as needed (fixedAmount, collections, etc.)
    const variables = {
      basicCodeDiscount: {
        title: `Thank You ${code}`,
        startsAt: startsAt.toISOString(),
        endsAt: endsAt.toISOString(),
        code,
        customerGets: {
          value: { percentage: 10 }, // or { fixedAmount: { amount: "5.00" } }
          items: { all: true }       // restrict to a collection via items: { collections: { add: ["gid://shopify/Collection/123"] } }
        },
        combinesWith: { orderDiscounts: true, productDiscounts: false, shippingDiscounts: false },
        usageLimit: 1,     // set to null for unlimited; adjust if you want single-use
        appliesOncePerCustomer: true
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

    const data = await r.json();
    if (!r.ok) {
      console.error('Shopify HTTP error', r.status, data);
      return res.status(502).json({ error: 'Shopify HTTP error', status: r.status, details: data });
    }

    const errs = data?.data?.discountCodeBasicCreate?.userErrors;
    if (errs?.length) {
      console.error('Shopify userErrors', errs);
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
  } catch (e: any) {
    console.error('Unhandled error creating discount', e);
    return res.status(500).json({ error: 'Unhandled error', message: e?.message });
  }
}
