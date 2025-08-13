// CommonJS export so we don't depend on ESM config.
// Also supports GET for a quick "is the route alive?" check.

const ALLOW_ORIGINS = [
  "https://everlymade.com",
  "https://everlymade.myshopify.com"
];

function setCors(res, origin) {
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

module.exports = async (req, res) => {
  try {
    const origin = req.headers.origin || "";
    const allowed = ALLOW_ORIGINS.includes(origin) ? origin : ALLOW_ORIGINS[0];
    setCors(res, allowed);

    // Quick health check that does NOT call Shopify
    if (req.method === "GET") {
      return res.status(200).json({ ok: true, route: "thankyouclaim" });
    }

    if (req.method === "OPTIONS") return res.status(204).end();
    if (req.method !== "POST") return res.status(405).json({ message: "Method not allowed" });

    // Parse body
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const now = new Date();
    const endsAtISO = body?.expiresAt
      ? new Date(body.expiresAt).toISOString()
      : new Date(now.getTime() + 20 * 60 * 1000).toISOString(); // default 20 min

    const code = "QR-" + Math.random().toString(16).slice(2, 10).toUpperCase();
    const shop   = process.env.SHOPIFY_SHOP;           // e.g., everlymade.myshopify.com
    const token  = process.env.SHOPIFY_ADMIN_TOKEN;    // admin API access token (Custom App)
    const pct    = Number(process.env.QR_PERCENT || "20");

    if (!shop || !token) {
      return res.status(500).json({ message: "Missing SHOPIFY_SHOP or SHOPIFY_ADMIN_TOKEN" });
    }

    // Build Shopify GraphQL call (using global fetch on Vercel/Node 18+)
    const query = `
      mutation discountCodeBasicCreate($basic: DiscountCodeBasicInput!) {
        discountCodeBasicCreate(basic: $basic) {
          codeDiscountNode { id }
          userErrors { field message }
        }
      }`;
    const variables = {
      basic: {
        title: `QR Flash ${pct}%`,
        startsAt: now.toISOString(),
        endsAt: endsAtISO,
        customerGets: { items: { all: true }, value: { percentage: pct / 100 } },
        usageLimit: 1,
        appliesOncePerCustomer: true,
        codes: [{ code }]
      }
    };

    const resp = await fetch(`https://${shop}/admin/api/2024-07/graphql.json`, {
      method: "POST",
      headers: { "X-Shopify-Access-Token": token, "Content-Type": "application/json" },
      body: JSON.stringify({ query, variables })
    });

    const json = await resp.json().catch(() => ({}));
    const errs = json?.data?.discountCodeBasicCreate?.userErrors;
    if (errs?.length) return res.status(400).json({ message: errs.map(e => e.message).join("; ") });

    return res.status(200).json({ code, expiresAt: endsAtISO });
  } catch (e) {
    console.error("Function error:", e);
    return res.status(500).json({ message: "Failed to create discount" });
  }
};
