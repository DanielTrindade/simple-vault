import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const brokerExe = process.argv[2];
const mcpEntry = process.argv[3];

if (!brokerExe || !mcpEntry) {
  console.error("uso: node mcp-smoke.mjs <svault-broker.exe> <index.mjs>");
  process.exit(1);
}

const home = mkdtempSync(join(tmpdir(), "svault-mcp-"));
const pipeName = `svault.mcp.${Math.random().toString(16).slice(2, 10)}`;

let passed = 0;
let failed = 0;

function check(name, condition, detail = "") {
  if (condition) {
    passed++;
    console.log(`  [ok]   ${name}`);
  } else {
    failed++;
    console.log(`  [FALHA] ${name}${detail ? `: ${detail}` : ""}`);
  }
}

const broker = spawn(brokerExe, ["--console", "--in-memory-credentials", "--home", home, "--pipe", pipeName], {
  stdio: ["ignore", "pipe", "pipe"],
});
broker.stdout.on("data", () => {});
broker.stderr.on("data", (d) => process.stderr.write(`  [broker] ${d}`));

await new Promise((r) => setTimeout(r, 2500));

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
  const payload = { jsonrpc: "2.0", id, method, params };
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout em ${method}`)), 20000);
    pending.set(id, (message) => {
      clearTimeout(timer);
      resolve(message);
    });
    mcp.stdin.write(JSON.stringify(payload) + "\n");
  });
}

function notify(method, params) {
  mcp.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

try {
  let init = null;
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      init = await send("initialize", {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "svault-smoke", version: "1.0.0" },
      });
      if (init?.result) break;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  check("initialize responde", init?.result?.serverInfo?.name === "svault-mcp", JSON.stringify(init).slice(0, 160));
  notify("notifications/initialized", {});

  const tools = await send("tools/list", {});
  const names = (tools.result?.tools ?? []).map((t) => t.name).sort();
  check(
    "ferramentas expostas sao apenas as seguras",
    JSON.stringify(names) ===
      JSON.stringify([
        "vault_health",
        "vault_list_entries",
        "vault_list_operations",
        "vault_operation_status",
        "vault_request_operation",
      ]),
    JSON.stringify(names),
  );

  const forbidden = names.filter((n) =>
    /get_secret|read_password|reveal|export|decrypt/i.test(n),
  );
  check("nenhuma ferramenta devolve segredo", forbidden.length === 0, JSON.stringify(forbidden));

  const health = await send("tools/call", { name: "vault_health", arguments: {} });
  check("vault_health responde", !health.result?.isError, JSON.stringify(health).slice(0, 160));

  const entries = await send("tools/call", { name: "vault_list_entries", arguments: {} });
  const entriesText = entries.result?.content?.[0]?.text ?? "";
  check("vault_list_entries responde", !entries.result?.isError, entriesText.slice(0, 160));
  check("vault_list_entries nao contem segredo", !/value|senha|secret|password/i.test(entriesText), entriesText.slice(0, 160));

  const ops = await send("tools/call", { name: "vault_list_operations", arguments: {} });
  check("vault_list_operations responde", !ops.result?.isError);

  const req = await send("tools/call", {
    name: "vault_request_operation",
    arguments: { operationId: "inexistente" },
  });
  const reqText = req.result?.content?.[0]?.text ?? "";
  check(
    "vault_request_operation sinaliza erro de forma controlada",
    req.result?.isError === true && reqText.includes("not_found"),
    reqText.slice(0, 160),
  );

  const status = await send("tools/call", {
    name: "vault_operation_status",
    arguments: { requestId: "inexistente" },
  });
  check(
    "vault_operation_status sinaliza erro de forma controlada",
    status.result?.isError === true,
    JSON.stringify(status).slice(0, 160),
  );
} catch (error) {
  failed++;
  console.log(`  [FALHA] execucao do teste MCP: ${error.message}`);
  const { readFileSync, existsSync } = await import("node:fs");
  const logPath = join(home, "logs", "svault-broker.log");
  if (existsSync(logPath)) {
    console.log("  --- log do broker ---");
    console.log(readFileSync(logPath, "utf8").split("\n").slice(-12).join("\n"));
  }
} finally {
  mcp.kill();
  broker.kill();
  try {
    rmSync(home, { recursive: true, force: true });
  } catch {}
}

console.log();
console.log(`resultado: ${passed} aprovado(s), ${failed} falha(s)`);
process.exit(failed === 0 ? 0 : 1);
