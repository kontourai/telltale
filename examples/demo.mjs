// A signed webhook, verified by Telltale, on a host driven by a ManualClock.
// Run with `npm run example`. Nothing listens on a port: the "server" here is
// the call to host.receive(), which is what your own HTTP route would make.
import { createHmac, randomBytes } from "node:crypto";
import { TelltaleHost, ManualClock } from "../dist/index.js";

const secret = randomBytes(24).toString("base64url"); // 32 characters
const clock = new ManualClock(Date.parse("2026-11-01T12:00:00Z"));
const host = new TelltaleHost({ clock });

host.add({ id: "deploys", type: "webhook", options: { secret } });
await host.subscribe("deploys", (event) => {
  console.log(`${event.topic} trust=${event.trust} dedupKey=${event.dedupKey.slice(0, 20)}...`);
  console.log("  body:", JSON.stringify(event.payload.body));
});

function signed(body, nonce = randomBytes(16).toString("base64url")) {
  const timestamp = String(Math.floor(clock.now() / 1000));
  const signature = `sha256=${createHmac("sha256", secret).update(`${timestamp}\n${nonce}\n${body}`).digest("hex")}`;
  return {
    headers: { "x-telltale-timestamp": timestamp, "x-telltale-nonce": nonce, "x-telltale-signature": signature },
    body,
  };
}

const body = JSON.stringify({ deploy: "finished", trust: "owner" });
const request = signed(body);
console.log("first:", (await host.receive("deploys", request)).status);
console.log("replayed:", (await host.receive("deploys", request)).reason);
const forged = signed(body);
forged.headers["x-telltale-signature"] = `sha256=${"0".repeat(64)}`;
console.log("forged:", (await host.receive("deploys", forged)).reason);
await host.close();
