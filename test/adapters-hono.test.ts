import { createOAuthApp } from "../src/adapters/hono.ts";
import { runAdapterFlow, type AdapterClient, type AdapterResp } from "./lib/adapter-flow.ts";

runAdapterFlow("hono", async (bridge, identity) => {
  const app = createOAuthApp({ bridge, identity });
  const client: AdapterClient = {
    async get(path, headers) {
      const r = await app.request(path, { method: "GET", headers: headers ?? {} });
      return { status: r.status, headers: Object.fromEntries(r.headers), body: await r.text() } as AdapterResp;
    },
    async postForm(path, body, headers) {
      const r = await app.request(path, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams(body).toString() });
      return { status: r.status, headers: Object.fromEntries(r.headers), body: await r.text() } as AdapterResp;
    },
    async postJson(path, body, headers) {
      const r = await app.request(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
      return { status: r.status, headers: Object.fromEntries(r.headers), body: await r.text() } as AdapterResp;
    },
  };
  return client;
});
