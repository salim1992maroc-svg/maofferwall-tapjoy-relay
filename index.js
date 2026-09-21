async function md5(text) {
  const data = new TextEncoder().encode(text);

  const hash = await crypto.subtle.digest("MD5", data);

  return [...new Uint8Array(hash)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

export default {
  async fetch(request, env) {
    if (request.method !== "GET") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const incoming = new URL(request.url);

    const id = incoming.searchParams.get("id");
    const snuid = incoming.searchParams.get("snuid");
    const currency = incoming.searchParams.get("currency");
    const verifier = incoming.searchParams.get("verifier");
    const macAddress = incoming.searchParams.get("mac_address");

    // Required Tapjoy parameters
    if (!id || !snuid || !currency || !verifier) {
      return new Response("Missing parameters", { status: 403 });
    }

    // Tapjoy verifier:
    // MD5(id:snuid:currency:secret)
    const raw =
      `${id}:${snuid}:${currency}:${env.TAPJOY_VIRTUAL_CURRENCY_SECRET}`;

    const expected = await md5(raw);

    if (expected.toLowerCase() !== verifier.toLowerCase()) {
      return new Response("Invalid verifier", { status: 403 });
    }

    // Forward ONLY after successful verification
    const target = new URL(env.WHACKA_WEBHOOK_URL);

    target.searchParams.set("provider", "tapjoy");
    target.searchParams.set("id", id);
    target.searchParams.set("snuid", snuid);
    target.searchParams.set("currency", currency);
    target.searchParams.set("verifier", verifier);

    if (macAddress) {
      target.searchParams.set("mac_address", macAddress);
    }

    const response = await fetch(target.toString(), {
      method: "GET"
    });

    if (!response.ok) {
      return new Response("Whacka webhook failed", { status: 502 });
    }

    return new Response("OK", { status: 200 });
  }
};
