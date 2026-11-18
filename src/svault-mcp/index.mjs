import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Shim de compatibilidade sem dependências externas: delega stdio ao binário nativo svault-mcp.exe.
const here = dirname(fileURLToPath(import.meta.url));
const candidates = [
  process.env.SVAULT_MCP_EXE,
  join(here, "..", "svault-mcp.exe"),
  join(here, "svault-mcp.exe"),
  join(here, "..", "..", "target", "release", "svault-mcp.exe"),
  join(here, "..", "..", "target", "x86_64-pc-windows-msvc", "release", "svault-mcp.exe"),
  join(here, "..", "..", "target", "x86_64-pc-windows-gnu", "release", "svault-mcp.exe"),
  join(here, "..", "..", "target", "debug", "svault-mcp.exe"),
].filter(Boolean);

const exe = candidates.find((p) => existsSync(p));
if (!exe) {
  process.stderr.write("erro: executavel nativo svault-mcp.exe nao encontrado.\n");
  process.exit(1);
}

const child = spawn(exe, process.argv.slice(2), {
  stdio: "inherit",
  env: process.env,
});

child.on("error", (err) => {
  process.stderr.write(`erro ao iniciar svault-mcp.exe: ${err.message}\n`);
  process.exit(1);
});

child.on("exit", (code) => {
  process.exit(code ?? 1);
});
