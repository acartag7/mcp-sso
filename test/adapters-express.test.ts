import { request } from "node:http";
import express from "express";
import { createOAuthRouter } from "../src/adapters/express.ts";
import { runAdapterFlow, type AdapterClient, type AdapterResp } from "./lib/adapter-flow.ts";

runAdapterFlow("express", async (bridge, identity) => {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use("/", createOAuthRouter({ bridge, identity }));
  const server = app.listen(0, "127.0.0.1"); // express app.listen returns a Server
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const port = (server.address() as { port: number }).port;
  const base = `http://127.0.0.1:${port}`;

  // Raw HTTP (no redirect following) so 302s are captured, not chased to client.test.
  function call(method: string, path: string, headers: Record<string, string>, body?: string): Promise<AdapterResp> {
    return new Promise((resolve, reject) => {
      const url = new URL(base + path);
      const req = request({ hostname: url.hostname, port: url.port, path: url.pathname + url.search, method, headers }, (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c: string) => { buf += c; });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers as Record<string, string>, body: buf }));
      });
      req.on("error", reject);
      if (body !== undefined) req.write(body);
      req.end();
    });
  }
  const client: AdapterClient = {
    async get(path, headers) { return call("GET", path, headers ?? {}); },
    async postForm(path, body, headers) { return call("POST", path, { "content-type": "application/x-www-form-urlencoded", ...headers }, new URLSearchParams(body).toString()); },
    async postJson(path, body, headers) { return call("POST", path, { "content-type": "application/json", ...headers }, JSON.stringify(body)); },
    async close() { await new Promise<void>((resolve) => server.close(() => resolve())); },
  };
  return client;
}, "127.0.0.1");
