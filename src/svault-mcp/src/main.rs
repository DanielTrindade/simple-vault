use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Write};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use svault_client::{BrokerClient, BrokerError};

const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";

enum FramingMode {
    Newline,
    ContentLength,
}

fn main() {
    let client = BrokerClient::from_env();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    while let Some((raw, mode)) = read_rpc_message(&mut reader) {
        let Ok(message) = serde_json::from_str::<Value>(&raw) else {
            let err_resp = json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": { "code": -32700, "message": "Parse error" }
            });
            let _ = write_rpc_message(&mut writer, &err_resp, &mode);
            continue;
        };

        if let Some(response) = handle_rpc(&client, &message)
            && write_rpc_message(&mut writer, &response, &mode).is_err()
        {
            break;
        }
    }
}

fn read_rpc_message<R: BufRead>(reader: &mut R) -> Option<(String, FramingMode)> {
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).ok()?;
        if bytes == 0 {
            return None;
        }
        let trimmed = line.trim_start_matches('\u{feff}').trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(rest) = trimmed
            .strip_prefix("Content-Length:")
            .or_else(|| trimmed.strip_prefix("content-length:"))
        {
            let length: usize = rest.trim().parse().ok()?;
            // Consume remaining headers up to blank line
            loop {
                let mut hdr = String::new();
                let n = reader.read_line(&mut hdr).ok()?;
                if n == 0 || hdr.trim().is_empty() {
                    break;
                }
            }
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).ok()?;
            let text = String::from_utf8(body).ok()?;
            return Some((text, FramingMode::ContentLength));
        }

        return Some((trimmed.to_owned(), FramingMode::Newline));
    }
}

fn write_rpc_message<W: Write>(
    writer: &mut W,
    response: &Value,
    mode: &FramingMode,
) -> io::Result<()> {
    let payload = serde_json::to_string(response)?;
    match mode {
        FramingMode::Newline => {
            writer.write_all(payload.as_bytes())?;
            writer.write_all(b"\n")?;
        }
        FramingMode::ContentLength => {
            write!(writer, "Content-Length: {}\r\n\r\n", payload.len())?;
            writer.write_all(payload.as_bytes())?;
        }
    }
    writer.flush()
}

fn handle_rpc(client: &BrokerClient, message: &Value) -> Option<Value> {
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let id = message.get("id").cloned();

    // JSON-RPC notifications have no "id" and must not receive a response.
    let id = id?;

    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

    match method {
        "initialize" => {
            let requested_version = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .filter(|v| !v.trim().is_empty())
                .unwrap_or(DEFAULT_PROTOCOL_VERSION);

            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": requested_version,
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "svault-mcp",
                        "version": "1.0.0"
                    }
                }
            }))
        }
        "ping" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": tools_definition()
            }
        })),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));

            match call_tool_with_retry(client, name, &args) {
                Ok(data) => {
                    let text = serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".into());
                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{ "type": "text", "text": text }]
                        }
                    }))
                }
                Err(err_msg) => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "isError": true,
                        "content": [{ "type": "text", "text": format!("erro: {err_msg}") }]
                    }
                })),
            }
        }
        _ => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": format!("Method not found: {method}")
            }
        })),
    }
}

fn call_tool_with_retry(client: &BrokerClient, name: &str, args: &Value) -> Result<Value, String> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match call_tool_once(client, name, args) {
            Ok(val) => return Ok(val),
            Err(ToolCallError::Validation(msg)) => return Err(msg),
            Err(ToolCallError::Broker(err)) => {
                if err.is_unavailable() && attempt < 3 {
                    thread::sleep(Duration::from_millis(200));
                    continue;
                }
                if err.is_unavailable() {
                    return Err(err.message);
                }
                return Err(format!("{}: {}", err.code, err.message));
            }
        }
    }
}

enum ToolCallError {
    Validation(String),
    Broker(BrokerError),
}

impl From<BrokerError> for ToolCallError {
    fn from(err: BrokerError) -> Self {
        Self::Broker(err)
    }
}

fn call_tool_once(
    client: &BrokerClient,
    name: &str,
    args: &Value,
) -> Result<Value, ToolCallError> {
    match name {
        "vault_health" => Ok(client.send_raw("health", Some(&json!({})))?),
        "vault_list_entries" => Ok(client.send_raw("list_entries", Some(&json!({})))?),
        "vault_list_operations" => Ok(client.send_raw("list_operations", Some(&json!({})))?),
        "vault_request_operation" => {
            let op_id = args
                .get("operationId")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    ToolCallError::Validation("operationId e obrigatorio".to_owned())
                })?;

            let mut params_map = BTreeMap::new();
            if let Some(params_val) = args.get("params")
                && !params_val.is_null()
            {
                let Some(obj) = params_val.as_object() else {
                    return Err(ToolCallError::Validation(
                        "params deve ser um objeto de strings".to_owned(),
                    ));
                };
                for (k, v) in obj {
                    let Some(s) = v.as_str() else {
                        return Err(ToolCallError::Validation(format!(
                            "parametro {k} deve ser texto"
                        )));
                    };
                    params_map.insert(k.clone(), s.to_owned());
                }
            }

            Ok(client.send_raw(
                "request_operation",
                Some(&json!({
                    "opId": op_id,
                    "params": params_map
                })),
            )?)
        }
        "vault_operation_status" => {
            let request_id = args
                .get("requestId")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| ToolCallError::Validation("requestId e obrigatorio".to_owned()))?;

            Ok(client.send_raw("operation_status", Some(&json!({ "requestId": request_id })))?)
        }
        other => Err(ToolCallError::Validation(format!(
            "ferramenta desconhecida: {other}"
        ))),
    }
}

fn tools_definition() -> Value {
    json!([
        {
            "name": "vault_health",
            "description": "Verifica se o cofre SVault esta disponivel. Retorna apenas situacao, identidade do servico e contagens. Nao retorna nenhum valor de segredo.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "vault_list_entries",
            "description": "Lista os identificadores de segredos disponiveis no cofre (ex.: CPF_PESSOAL, SENHA_PORTAL_A) com metadados de tipo, alvos autorizados e data de atualizacao. NUNCA retorna o valor do segredo, apenas o identificador. Use esta ferramenta para descobrir quais credenciais podem ser usadas em uma tarefa.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "vault_list_operations",
            "description": "Lista as operacoes previamente autorizadas pelo proprietario, ou seja, as acoes que podem usar um segredo. Cada operacao tem um alvo fixo, um registro associado e uma lista de parametros que voce pode preencher. Nao existe forma de ler um segredo: apenas solicitar operacoes autorizadas.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "vault_request_operation",
            "description": "Solicita a execucao de uma operacao autorizada. O broker executa a acao usando o segredo e devolve apenas um resultado sanitizado (o valor do segredo e substituido por ***REDACTED***). Quando a operacao exige confirmacao humana, o status retornado e 'pending_approval': aguarde o proprietario aprovar no SVault Manager ou via svaultctl e depois consulte vault_operation_status. Nao repita a solicitacao: aguarde a aprovacao.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "operationId": {
                        "type": "string",
                        "description": "Identificador da operacao, conforme vault_list_operations."
                    },
                    "params": {
                        "type": "object",
                        "description": "Valores para os parametros declarados da operacao. Apenas chaves previamente autorizadas; nunca inclua o valor do segredo.",
                        "additionalProperties": { "type": "string" }
                    }
                },
                "required": ["operationId"],
                "additionalProperties": false
            }
        },
        {
            "name": "vault_operation_status",
            "description": "Consulta o andamento de uma solicitacao de operacao. Retorna o status (pending_approval, completed, failed, rejected, expired) e o resultado sanitizado quando concluido. Nunca retorna o valor do segredo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "requestId": {
                        "type": "string",
                        "description": "Identificador da solicitacao devolvido por vault_request_operation."
                    }
                },
                "required": ["requestId"],
                "additionalProperties": false
            }
        }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_list_exposes_only_safe_tools() {
        let tools = tools_definition();
        let mut names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "vault_health",
                "vault_list_entries",
                "vault_list_operations",
                "vault_operation_status",
                "vault_request_operation",
            ]
        );
    }
}
