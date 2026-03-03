#!/usr/bin/env node
"use strict";

const http       = require("http");
const httpProxy  = require("http-proxy");
const { program } = require("commander");
const chalk      = require("chalk");

// ── Config ────────────────────────────────────────────────────────────────────
const CODEASTRA_URL = process.env.CODEASTRA_URL
  || "https://app.codeastra.dev";

program
  .name("codeastra")
  .description("One-line security gateway for AI agents")
  .version("1.0.0");

program
  .command("proxy")
  .description("Wrap your agent with a security gateway — zero code changes")
  .requiredOption("--target <url>",  "Your agent's URL (e.g. http://localhost:8080)")
  .option("--port <port>",           "Port to listen on", "4000")
  .option("--agent-id <id>",         "Agent ID (or set CODEASTRA_AGENT_ID)")
  .option("--api-key <key>",         "API key (or set CODEASTRA_API_KEY)")
  .option("--tool-header <header>",  "Header that contains the tool name", "x-tool")
  .option("--passthrough",           "Allow requests even if Codeastra is unreachable", false)
  .action(runProxy);

program.parse();

// ── Proxy ─────────────────────────────────────────────────────────────────────
async function runProxy(opts) {
  const apiKey  = opts.apiKey  || process.env.CODEASTRA_API_KEY;
  const agentId = opts.agentId || process.env.CODEASTRA_AGENT_ID;
  const port    = parseInt(opts.port, 10);

  // ── Banner ─────────────────────────────────────────────────────────────────
  console.log();
  console.log(chalk.bold.cyan("  🛡  Codeastra Proxy"));
  console.log(chalk.dim("  ─────────────────────────────────────"));
  console.log(`  ${chalk.bold("Listening")}  →  ${chalk.cyan(`http://localhost:${port}`)}`);
  console.log(`  ${chalk.bold("Forwarding")} →  ${chalk.cyan(opts.target)}`);
  console.log(`  ${chalk.bold("Gateway")}    →  ${chalk.cyan(CODEASTRA_URL)}`);
  console.log();

  if (!apiKey) {
    console.log(chalk.yellow("  ⚠  No API key — run: codeastra init"));
    console.log(chalk.dim("     Or set CODEASTRA_API_KEY env var"));
    console.log(chalk.dim("     Requests will pass through unguarded\n"));
  } else {
    console.log(`  ${chalk.green("✓")} API key loaded`);
  }
  if (agentId) {
    console.log(`  ${chalk.green("✓")} Agent: ${agentId}`);
  }
  console.log();
  console.log(chalk.dim("  Waiting for requests...\n"));

  // ── Proxy server ───────────────────────────────────────────────────────────
  const proxy = httpProxy.createProxyServer({ changeOrigin: true });

  const server = http.createServer(async (req, res) => {
    const start = Date.now();

    // Collect request body
    const bodyChunks = [];
    for await (const chunk of req) bodyChunks.push(chunk);
    const rawBody = Buffer.concat(bodyChunks);
    let body = {};
    try { body = JSON.parse(rawBody.toString()); } catch {}

    // Extract tool name — check multiple common conventions
    const tool = (
      req.headers[opts.toolHeader.toLowerCase()] ||
      req.headers["x-tool-name"]                 ||
      body.tool                                   ||
      body.function                               ||
      body.action                                 ||
      inferToolFromPath(req.url)
    );

    const userId = (
      req.headers["x-user-id"]  ||
      body.user_id               ||
      body.userId                ||
      "proxy_user"
    );

    // ── Check with Codeastra ─────────────────────────────────────────────────
    if (apiKey && agentId && tool) {
      const decision = await checkCodeastra({ apiKey, agentId, tool, body, userId });
      const ms = Date.now() - start;

      if (!decision.allowed) {
        const icon = chalk.red("✗ BLOCKED");
        const reason = chalk.dim(decision.reason || "policy");
        console.log(`  ${icon}  ${chalk.bold(tool.padEnd(25))} ${reason}  ${chalk.dim(`${ms}ms`)}`);

        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          error:   "blocked_by_policy",
          tool,
          reason:  decision.reason,
          policy:  decision.policy,
        }));
        return;
      }

      const icon = chalk.green("✓ ALLOW ");
      const policy = chalk.dim(decision.policy || "");
      console.log(`  ${icon}  ${chalk.bold(tool.padEnd(25))} ${policy}  ${chalk.dim(`${ms}ms`)}`);

      // Inject sanitized args back into body if redacted
      if (decision.redacted && decision.args) {
        const newBody = JSON.stringify({ ...body, ...decision.args });
        req.headers["content-length"] = Buffer.byteLength(newBody).toString();
        // Rebuild the request stream with sanitized body
        const { Readable } = require("stream");
        const stream = new Readable();
        stream.push(newBody);
        stream.push(null);
        req.pipe = stream.pipe.bind(stream);
        req._read = () => {};
        Object.assign(req, stream);
      }

    } else {
      // No Codeastra config — passthrough with warning
      if (!tool) {
        console.log(chalk.dim(`  → PASS   ${req.method} ${req.url}`));
      }

      // Rebuild request stream for proxy
      const { Readable } = require("stream");
      const stream = new Readable();
      stream.push(rawBody);
      stream.push(null);
      req.pipe = stream.pipe.bind(stream);
      req._read = () => {};
      Object.assign(req, stream);
    }

    // ── Forward to target ────────────────────────────────────────────────────
    // Re-attach body to request for proxying
    req.headers["content-length"] = rawBody.length.toString();
    const { Readable } = require("stream");
    const bodyStream = new Readable();
    bodyStream.push(rawBody);
    bodyStream.push(null);

    proxy.web(
      Object.assign(req, bodyStream),
      res,
      { target: opts.target, buffer: bodyStream },
      (err) => {
        console.log(chalk.red(`  ✗ Proxy error: ${err.message}`));
        res.writeHead(502);
        res.end(JSON.stringify({ error: "upstream_unavailable", detail: err.message }));
      }
    );
  });

  server.listen(port);
}

// ── Codeastra check ───────────────────────────────────────────────────────────
async function checkCodeastra({ apiKey, agentId, tool, body, userId }) {
  try {
    const payload = JSON.stringify({
      tool,
      args:     body.args || body.parameters || body.input || body,
      agent_id: agentId,
      user_id:  userId,
    });

    const url = new URL("/protect", CODEASTRA_URL);
    const res = await fetch(url.toString(), {
      method:  "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key":    apiKey,
      },
      body: payload,
      signal: AbortSignal.timeout(5000),
    });

    return await res.json();
  } catch (err) {
    // Network error — fail closed by default (deny)
    console.log(chalk.yellow(`  ⚠ Codeastra unreachable: ${err.message}`));
    return { allowed: false, reason: "codeastra_unreachable" };
  }
}

// ── Infer tool name from URL path ─────────────────────────────────────────────
function inferToolFromPath(url) {
  if (!url) return null;
  // /api/tools/sql_query → sql_query
  // /invoke/transfer_money → transfer_money
  const parts = url.split("/").filter(Boolean);
  const toolKeywords = ["tool", "invoke", "run", "execute", "call", "action", "function"];
  for (let i = 0; i < parts.length - 1; i++) {
    if (toolKeywords.includes(parts[i].toLowerCase())) {
      return parts[i + 1].split("?")[0];
    }
  }
  // Last path segment as fallback
  const last = parts[parts.length - 1];
  return last ? last.split("?")[0] : null;
}
