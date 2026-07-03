import Fastify from "fastify";
import { registerOAuthRoutes } from "../src/adapters/fastify.ts";
import { runAdapterFlow, type AdapterClient, type AdapterResp } from "./lib/adapter-flow.ts";

runAdapterFlow("fastify", async (bridge, identity) => {
  const app = Fastify();
  await registerOAuthRoutes(app, { bridge, identity });
  const resp = (r: { statusCode: number; headers: Record<string, unknown>; body: string }): AdapterResp =>
    ({ status: r.statusCode, headers: r.headers as Record<string, string>, body: r.body });
  const client: AdapterClient = {
    async get(path, headers) { return resp(await app.inject({ method: "GET", url: path, headers: headers ?? {} })); },
    async postForm(path, body, headers) {
      return resp(await app.inject({ method: "POST", url: path, headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, payload: new URLSearchParams(body).toString() }));
    },
    async postJson(path, body, headers) {
      return resp(await app.inject({ method: "POST", url: path, headers: { "content-type": "application/json", ...headers }, payload: JSON.stringify(body) }));
    },
    async close() { await app.close(); },
  };
  return client;
});
