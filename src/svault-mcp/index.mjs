import net from "node:net";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const pipeName = process.env.SVAULT_PIPE ?? "svault.broker.v1";
const PIPE_PATH = pipeName.startsWith("\\\\")
  ? pipeName
  : `\\\\.\\pipe\\${pipeName}`;
const PIPE_TIMEOUT_MS = Number(process.env.SVAULT_TIMEOUT_MS ?? 30000);
const MAX_RESPONSE_BYTES = 1024 * 1024;

const server = new Server(
  { name: "svault-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

const TOOLS = [
  {
    name: "vault_health",
    description:
      "Verifica se o cofre SVault esta disponivel. Retorna apenas situacao, identidade do servico e contagens. " +
      "Nao retorna nenhum valor de segredo.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "vault_list_entries",
    description:
      "Lista os identificadores de segredos disponiveis no cofre (ex.: CPF_PESSOAL, SENHA_PORTAL_A) com metadados " +
      "de tipo, alvos autorizados e data de atualizacao. NUNCA retorna o valor do segredo, apenas o identificador. " +
      "Use esta ferramenta para descobrir quais credenciais podem ser usadas em uma tarefa.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "vault_list_operations",
    description:
      "Lista as operacoes previamente autorizadas pelo proprietario, ou seja, as acoes que podem usar um segredo. " +
      "Cada operacao tem um alvo fixo, um registro associado e uma lista de parametros que voce pode preencher. " +
      "Nao existe forma de ler um segredo: apenas solicitar operacoes autorizadas.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "vault_request_operation",
    description:
      "Solicita a execucao de uma operacao autorizada. O broker executa a acao usando o segredo e devolve apenas um " +
      "resultado sanitizado (o valor do segredo e substituido por ***REDACTED***). " +
      "Quando a operacao exige confirmacao humana, o status retornado e 'pending_approval': aguarde o proprietario " +
      "aprovar no SVault Manager ou via svaultctl e depois consulte vault_operation_status. " +
      "Nao repita a solicitacao: aguarde a aprovacao.",
    inputSchema: {
      type: "object",
      properties: {
        operationId: {
          type: "string",
          description: "Identificador da operacao, conforme vault_list_operations.",
        },
        params: {
          type: "object",
          description:
            "Valores para os parametros declarados da operacao. Apenas chaves previamente autorizadas; nunca inclua o valor do segredo.",
          additionalProperties: { type: "string" },
        },
      },
      required: ["operationId"],
      additionalProperties: false,
    },
  },
  {
    name: "vault_operation_status",
    description:
      "Consulta o andamento de uma solicitacao de operacao. Retorna o status (pending_approval, completed, failed, " +
      "rejected, expired) e o resultado sanitizado quando concluido. Nunca retorna o valor do segredo.",
    inputSchema: {
      type: "object",
      properties: {
        requestId: {
          type: "string",
          description: "Identificador da solicitacao devolvido por vault_request_operation.",
        },
      },
      required: ["requestId"],
      additionalProperties: false,
    },
  },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    const data = await call(name, args ?? {});
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  } catch (error) {
    return {
      isError: true,
      content: [{ type: "text", text: `erro: ${error.message}` }],
    };
  }
});

async function call(cmd, body) {
  switch (cmd) {
    case "vault_health":
      return send("health", {});
    case "vault_list_entries":
      return send("list_entries", {});
    case "vault_list_operations":
      return send("list_operations", {});
    case "vault_request_operation": {
      const operationId = body.operationId;
      if (typeof operationId !== "string" || operationId.length === 0) {
        throw new Error("operationId e obrigatorio");
      }
      const params = body.params && typeof body.params === "object" ? body.params : {};
      return send("request_operation", { opId: operationId, params });
    }
    case "vault_operation_status": {
      const requestId = body.requestId;
      if (typeof requestId !== "string" || requestId.length === 0) {
        throw new Error("requestId e obrigatorio");
      }
      return send("operation_status", { requestId });
    }
    default:
      throw new Error(`ferramenta desconhecida: ${cmd}`);
  }
}

function send(cmd, body) {
  return withRetry(() => exchange(cmd, body));
}

function withRetry(operation) {
  return new Promise((resolve, reject) => {
    let attempt = 0;
    const run = () => {
      attempt += 1;
      operation().then(resolve, (error) => {
        const transient = /ENOENT|ECONNRESET|EPIPE/i.test(error.message ?? "");
        if (transient && attempt < 3) {
          setTimeout(run, 200);
          return;
        }
        reject(error);
      });
    };
    run();
  });
}

function exchange(cmd, body) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify({ cmd, body }), "utf8");
    const frame = Buffer.allocUnsafe(4 + payload.length);
    frame.writeInt32LE(payload.length, 0);
    payload.copy(frame, 4);

    const socket = net.connect(PIPE_PATH);
    const chunks = [];
    let expected = null;
    let settled = false;

    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };

    const timer = setTimeout(() => {
      finish(new Error("tempo esgotado ao falar com o broker SVault"));
    }, PIPE_TIMEOUT_MS);

    socket.on("error", (error) => {
      finish(new Error(`broker SVault indisponivel: ${error.message}`));
    });

    socket.on("end", () => {
      finish(new Error("conexao encerrada pelo broker antes da resposta"));
    });

    socket.on("close", () => {
      finish(new Error("conexao fechada pelo broker antes da resposta"));
    });

    socket.on("connect", () => {
      socket.write(frame);
    });

    socket.on("data", (chunk) => {
      chunks.push(chunk);
      const buffer = Buffer.concat(chunks);
      if (expected === null) {
        if (buffer.length < 4) return;
        expected = buffer.readInt32LE(0);
        if (expected <= 0 || expected > MAX_RESPONSE_BYTES) {
          finish(new Error("resposta invalida do broker"));
          return;
        }
      }
      if (buffer.length < 4 + expected) return;

      const response = JSON.parse(buffer.subarray(4, 4 + expected).toString("utf8"));
      if (!response.ok) {
        const code = response.error?.code ?? "error";
        const message = response.error?.message ?? "erro desconhecido";
        finish(new Error(`${code}: ${message}`));
        return;
      }
      finish(null, response.data ?? {});
    });
  });
}

const transport = new StdioServerTransport();
await server.connect(transport);
