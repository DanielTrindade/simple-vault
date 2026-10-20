import { spawn } from "node:child_process";

const mcpEntry = process.argv[2];
const pipeName = process.argv[3] ?? "svault.broker.v1";

if (!mcpEntry) {
  console.error("uso: node agent-view.mjs <index.mjs> [pipe]");
  process.exit(1);
}

const mcp = spawn(process.execPath, [mcpEntry], {
  env: { ...process.env, SVAULT_PIPE: pipeName },
  stdio: ["pipe", "pipe", "pipe"],
});

let buffer = "";
const pending = new Map();
let nextId = 1;

mcp.stdout.on("data", (chunk) => {
  buffer += chunk.toString();
  let index;
  while ((index = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, index).trim();
    buffer = buffer.slice(index + 1);
    if (!line) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      continue;
    }
    if (message.id !== undefined && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    }
  }
});

mcp.stderr.on("data", (d) => process.stderr.write(`  [mcp] ${d}`));

function send(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout em ${method}`)), 20000);
    pending.set(id, (message) => {
      clearTimeout(timer);
      resolve(message);
    });
    mcp.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

function notify(method, params) {
  mcp.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

async function callTool(name, args = {}) {
  const response = await send("tools/call", { name, arguments: args });
  const text = response.result?.content?.[0]?.text ?? "";
  return { isError: response.result?.isError === true, text };
}

try {
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      const init = await send("initialize", {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "agente-demo", version: "1.0.0" },
      });
      if (init?.result) break;
    } catch {
      await new Promise((r) => setTimeout(r, 400));
    }
  }
  notify("notifications/initialized", {});

  console.log("=== o que o MODELO enxerga (payload exato das ferramentas MCP) ===\n");

  const health = await callTool("vault_health");
  console.log("vault_health ->");
  console.log(health.text);
  console.log();

  const entries = await callTool("vault_list_entries");
  console.log("vault_list_entries ->");
  console.log(entries.text);
  console.log();

  const ops = await callTool("vault_list_operations");
  console.log("vault_list_operations ->");
  console.log(ops.text);
  console.log();

  const request = await callTool("vault_request_operation", {
    operationId: "login_portal_a",
    params: { usuario: "usuario-ficticio" },
  });
  console.log("vault_request_operation ->");
  console.log(request.text);
  console.log();

  const parsed = JSON.parse(request.text);
  const requestId = parsed.requestId;

  console.log("--- aguardando aprovacao do proprietario (aprovar com svaultctl) ---");
  console.log(`requestId: ${requestId}`);
  const statusFile = process.env.SVAULT_STATUS_FILE;
  if (statusFile) {
    const fs = await import("node:fs");
    fs.writeFileSync(statusFile, requestId);
  }
  console.log("(consulte: svaultctl status --request " + requestId + ")");
} catch (error) {
  console.log("erro: " + error.message);
  process.exitCode = 1;
} finally {
  mcp.kill();
}
