#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod broker;
mod chrome;
mod view;

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use slint::{ComponentHandle, Image, Model, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString, Timer, TimerMode, VecModel};
use zeroize::Zeroizing;

use broker::{BrokerClient, BrokerError, Entry, Health, OkResult, Operation, PendingRequest};

slint::include_modules!();

const POLL_INTERVAL: Duration = Duration::from_secs(3);
const TOAST_LIFETIME: Duration = Duration::from_millis(4500);
const MAX_TOASTS: usize = 4;

thread_local! {
    static CONTROLLER: RefCell<Option<Controller>> = const { RefCell::new(None) };
}

fn with<R>(f: impl FnOnce(&mut Controller) -> R) -> Option<R> {
    CONTROLLER.with(|cell| cell.borrow_mut().as_mut().map(f))
}

fn background<T: Send + 'static>(
    client: &BrokerClient,
    work: impl FnOnce(&BrokerClient) -> T + Send + 'static,
    done: impl FnOnce(&mut Controller, T) + Send + 'static,
) {
    let client = client.clone();
    thread::spawn(move || {
        let result = work(&client);
        let _ = slint::invoke_from_event_loop(move || {
            with(|c| done(c, result));
        });
    });
}

fn secret(value: SharedString) -> Zeroizing<String> {
    Zeroizing::new(value.as_str().to_owned())
}

struct Snapshot {
    health: Result<Health, BrokerError>,
    entries: Option<Vec<Entry>>,
    operations: Option<Vec<Operation>>,
    pending: Option<Vec<PendingRequest>>,
}

fn load_snapshot(client: &BrokerClient, lists: bool) -> Snapshot {
    let health = client.health();
    let ready = matches!(&health, Ok(h) if h.vault_initialized);
    Snapshot {
        entries: (ready && lists).then(|| client.list_entries().ok()).flatten(),
        operations: (ready && lists).then(|| client.list_operations().ok()).flatten(),
        pending: ready.then(|| client.pending_approvals().ok()).flatten(),
        health,
    }
}

struct Controller {
    app: AppWindow,
    client: BrokerClient,
    health: Health,
    entries: Vec<Entry>,
    operations: Vec<Operation>,
    approvals: Vec<PendingRequest>,
    known_requests: HashSet<String>,
    first_snapshot: bool,
    polling: bool,
    toast_seq: i32,
    entries_model: Rc<VecModel<EntryRow>>,
    operations_model: Rc<VecModel<OperationRow>>,
    approvals_model: Rc<VecModel<ApprovalRow>>,
    toasts_model: Rc<VecModel<ToastData>>,
    commands_model: Rc<VecModel<CommandItem>>,
}

impl Controller {
    fn store(&self) -> Store<'_> {
        self.app.global::<Store>()
    }

    fn set_busy(&self, busy: bool) {
        self.store().set_busy(busy);
    }

    fn refresh(&mut self) {
        self.set_busy(true);
        background(&self.client, |client| load_snapshot(client, true), |c, snapshot| {
            c.set_busy(false);
            c.apply_snapshot(snapshot);
        });
    }

    fn poll(&mut self) {
        if self.polling {
            return;
        }
        self.polling = true;
        let known = (self.health.entry_count, self.health.operation_count);
        background(
            &self.client,
            move |client| {
                let mut snapshot = load_snapshot(client, false);
                if let Ok(health) = &snapshot.health
                    && health.vault_initialized
                    && (health.entry_count, health.operation_count) != known
                {
                    snapshot.entries = client.list_entries().ok();
                    snapshot.operations = client.list_operations().ok();
                }
                snapshot
            },
            |c, snapshot| {
                c.polling = false;
                c.apply_snapshot(snapshot);
            },
        );
    }

    fn apply_snapshot(&mut self, snapshot: Snapshot) {
        let store = self.store();
        store.set_loaded(true);
        match snapshot.health {
            Ok(health) => {
                store.set_health(HealthData {
                    online: true,
                    initialized: health.vault_initialized,
                    totp: health.totp_required,
                    identity: health.service_identity.as_str().into(),
                    version: health.version.as_str().into(),
                    entries: health.entry_count,
                    operations: health.operation_count,
                    message: SharedString::new(),
                });
                self.health = health;
            }
            Err(error) => {
                store.set_health(HealthData { online: false, message: error.message.as_str().into(), ..Default::default() });
                self.health = Health::default();
                self.approvals.clear();
                self.render_approvals();
                return;
            }
        }

        if let Some(entries) = snapshot.entries {
            self.entries = entries;
        }
        if let Some(operations) = snapshot.operations {
            self.operations = operations;
        }
        self.render_entries();
        self.render_operations();

        if let Some(pending) = snapshot.pending {
            let fresh: Vec<&PendingRequest> =
                pending.iter().filter(|r| !self.known_requests.contains(&r.request_id)).collect();
            if !self.first_snapshot && !fresh.is_empty() {
                let first = fresh[0];
                let title = if fresh.len() == 1 {
                    "Nova solicitação de aprovação".to_owned()
                } else {
                    format!("{} novas solicitações de aprovação", fresh.len())
                };
                self.toast("info", &title, &format!("{} usando {}", first.summary.operation_id, first.summary.entry_id));
                chrome::flash_taskbar(self.app.window());
            }
            self.known_requests = pending.iter().map(|r| r.request_id.clone()).collect();
            self.approvals = pending;
            self.render_approvals();
        }
        self.first_snapshot = false;
    }

    fn render_entries(&self) {
        let store = self.store();
        let filter = store.get_entry_filter();
        let previous = self.selected_entry_id();
        let rows: Vec<EntryRow> = self
            .entries
            .iter()
            .filter(|e| view::entry_matches(e, &filter))
            .map(|entry| {
                let operations: Vec<SharedString> = self
                    .operations
                    .iter()
                    .filter(|o| o.entry_id == entry.id)
                    .map(|o| o.id.as_str().into())
                    .collect();
                EntryRow {
                    id: entry.id.as_str().into(),
                    label: entry.label.as_str().into(),
                    kind: entry.kind.as_str().into(),
                    kind_label: view::kind_label(&entry.kind).into(),
                    targets: ModelRc::new(VecModel::from(
                        entry.targets.iter().map(|t| SharedString::from(t.as_str())).collect::<Vec<_>>(),
                    )),
                    targets_text: entry.targets.join("\n").into(),
                    created: view::format_time(&entry.created_at).into(),
                    updated: view::format_time(&entry.updated_at).into(),
                    revision: entry.revision,
                    operations: ModelRc::new(VecModel::from(operations)),
                }
            })
            .collect();

        let selected = previous
            .and_then(|id| rows.iter().position(|r| r.id == id))
            .or(if rows.is_empty() { None } else { Some(0) });
        self.entries_model.set_vec(rows);
        store.set_selected_entry(selected.map_or(-1, |i| i as i32));
        store.set_total_entries(self.entries.len() as i32);
        store.set_entry_ids(ModelRc::new(VecModel::from(
            self.entries.iter().map(|e| SharedString::from(e.id.as_str())).collect::<Vec<_>>(),
        )));
        store.set_entry_labels(ModelRc::new(VecModel::from(
            self.entries
                .iter()
                .map(|e| SharedString::from(if e.label == e.id { "" } else { e.label.as_str() }))
                .collect::<Vec<_>>(),
        )));
    }

    fn selected_entry_id(&self) -> Option<SharedString> {
        let index = usize::try_from(self.store().get_selected_entry()).ok()?;
        self.entries_model.row_data(index).map(|r| r.id)
    }

    fn render_operations(&self) {
        let store = self.store();
        let filter = store.get_operation_filter();
        let previous = usize::try_from(store.get_selected_operation())
            .ok()
            .and_then(|i| self.operations_model.row_data(i))
            .map(|r| r.id);
        let rows: Vec<OperationRow> = self
            .operations
            .iter()
            .filter(|o| view::operation_matches(o, &filter))
            .map(|o| OperationRow {
                id: o.id.as_str().into(),
                entry: o.entry_id.as_str().into(),
                action: o.action.as_str().into(),
                action_label: view::action_label(&o.action).into(),
                target: o.target.as_str().into(),
                description: o.description.as_str().into(),
                params: o.params.join(", ").into(),
                requires_approval: o.requires_approval,
            })
            .collect();
        let selected = previous
            .and_then(|id| rows.iter().position(|r| r.id == id))
            .or(if rows.is_empty() { None } else { Some(0) });
        self.operations_model.set_vec(rows);
        store.set_selected_operation(selected.map_or(-1, |i| i as i32));
        store.set_total_operations(self.operations.len() as i32);
    }

    fn render_approvals(&self) {
        let store = self.store();
        let previous = usize::try_from(store.get_selected_approval())
            .ok()
            .and_then(|i| self.approvals_model.row_data(i))
            .map(|r| r.request_id);
        let now = chrono::Utc::now();
        let rows: Vec<ApprovalRow> = self
            .approvals
            .iter()
            .map(|request| {
                let summary = &request.summary;
                let countdown = view::countdown(&request.created_at, &request.expires_at, now);
                let params: Vec<ParamRow> = summary
                    .parameters
                    .iter()
                    .map(|(name, value)| ParamRow { name: name.as_str().into(), value: value.as_str().into() })
                    .collect();
                ApprovalRow {
                    request_id: request.request_id.as_str().into(),
                    operation: summary.operation_id.as_str().into(),
                    entry: summary.entry_id.as_str().into(),
                    target: summary.target.as_str().into(),
                    action: summary.action.as_str().into(),
                    action_label: view::request_label(request).into(),
                    method: summary.method.clone().unwrap_or_default().into(),
                    description: summary.description.as_str().into(),
                    auxiliary: summary.referenced_entries.join(", ").into(),
                    params: ModelRc::new(VecModel::from(params)),
                    created: view::format_time(&request.created_at).into(),
                    remaining: countdown.text.into(),
                    progress: countdown.progress,
                    urgent: countdown.urgent,
                }
            })
            .collect();
        let selected = previous.and_then(|id| rows.iter().position(|r| r.request_id == id)).unwrap_or(0);
        self.approvals_model.set_vec(rows);
        store.set_selected_approval(selected as i32);
    }

    fn tick(&self) {
        let now = chrono::Utc::now();
        for (index, request) in self.approvals.iter().enumerate() {
            let Some(mut row) = self.approvals_model.row_data(index) else { continue };
            let countdown = view::countdown(&request.created_at, &request.expires_at, now);
            if row.remaining != countdown.text.as_str() {
                row.remaining = countdown.text.into();
                row.progress = countdown.progress;
                row.urgent = countdown.urgent;
                self.approvals_model.set_row_data(index, row);
            }
        }
    }

    fn toast(&mut self, kind: &str, title: &str, message: &str) {
        self.toast_seq += 1;
        let id = self.toast_seq;
        while self.toasts_model.row_count() >= MAX_TOASTS {
            self.toasts_model.remove(0);
        }
        self.toasts_model.push(ToastData { id, kind: kind.into(), title: title.into(), message: message.into() });
        if kind != "error" {
            Timer::single_shot(TOAST_LIFETIME, move || {
                with(|c| c.dismiss_toast(id));
            });
        }
    }

    fn dismiss_toast(&self, id: i32) {
        if let Some(index) = self.toasts_model.iter().position(|t| t.id == id) {
            self.toasts_model.remove(index);
        }
    }

    fn fail(&mut self, error: &BrokerError) {
        if error.is_unavailable() {
            self.toast("error", "Broker indisponível", &error.message);
        } else {
            self.store().set_form_error(error.message.as_str().into());
        }
    }

    fn approve(&mut self, request_id: SharedString) {
        let store = self.store();
        let passphrase = secret(store.get_approval_passphrase());
        let totp = store.get_approval_totp().trim().to_owned();
        if passphrase.is_empty() {
            self.toast("warning", "Informe a senha do cofre", "A aprovação exige a senha do cofre.");
            return;
        }
        if self.health.totp_required && totp.is_empty() {
            self.toast("warning", "Informe o código TOTP", "Este cofre exige o código do autenticador.");
            return;
        }
        store.set_approval_passphrase(SharedString::new());
        store.set_approval_totp(SharedString::new());
        self.set_busy(true);

        let request = self.approvals.iter().find(|r| r.request_id == request_id.as_str()).cloned();
        let id = request_id.to_string();
        background(
            &self.client,
            move |client| client.approve(&id, &passphrase, (!totp.is_empty()).then_some(totp.as_str())),
            move |c, result| {
                c.set_busy(false);
                match result {
                    Ok(outcome) => c.show_result(request_id.as_str(), request.as_ref(), outcome),
                    Err(error) => c.toast("error", "Aprovação não concluída", &error.message),
                }
                c.poll();
            },
        );
    }

    fn show_result(&mut self, request_id: &str, request: Option<&PendingRequest>, outcome: OkResult) {
        let status = outcome.status.clone().unwrap_or_default();
        let operation = request.map(|r| r.summary.operation_id.clone()).unwrap_or_default();
        let ok = status == "completed" && outcome.result.as_ref().is_some_and(|r| r.ok);
        let result = outcome.result.unwrap_or_default();
        let code = match (result.status_code, result.exit_code) {
            (Some(status), _) => format!("HTTP {status}"),
            (None, Some(exit)) => format!("código de saída {exit}"),
            _ => String::new(),
        };
        let data = ResultData {
            request_id: request_id.into(),
            operation: operation.as_str().into(),
            ok,
            status: status.as_str().into(),
            kind: result.kind.as_str().into(),
            code: code.into(),
            duration: result.duration_ms.as_str().into(),
            output: result.body.or(result.output).unwrap_or_default().into(),
            error: outcome.error.unwrap_or_default().into(),
        };
        let store = self.store();
        store.set_result(data);
        store.set_modal("result".into());
        if ok {
            self.toast("success", "Operação executada", &operation);
        } else {
            self.toast("error", "A operação falhou", &format!("{operation}: {status}"));
        }
    }

    fn confirm(&mut self, passphrase: SharedString) {
        let passphrase = secret(passphrase);
        let confirm = self.store().get_confirm();
        let action = confirm.action.to_string();
        let subject = confirm.subject.to_string();
        self.store().set_form_error(SharedString::new());
        self.set_busy(true);
        background(
            &self.client,
            {
                let action = action.clone();
                let subject = subject.clone();
                move |client| match action.as_str() {
                    "delete-entry" => client.delete_entry(&subject, &passphrase).map(|_| ()),
                    "revoke-operation" => client.revoke_operation(&subject, &passphrase).map(|_| ()),
                    _ => client.reject(&subject, &passphrase).map(|_| ()),
                }
            },
            move |c, result| {
                c.set_busy(false);
                match result {
                    Ok(()) => {
                        c.store().invoke_close_modal();
                        let title = match action.as_str() {
                            "delete-entry" => "Registro removido",
                            "revoke-operation" => "Operação revogada",
                            _ => "Solicitação rejeitada",
                        };
                        c.toast("success", title, &subject);
                        c.refresh();
                    }
                    Err(error) => c.fail(&error),
                }
            },
        );
    }

    fn save_entry(&mut self, form: EntryForm) {
        let store = self.store();
        let passphrase = secret(form.passphrase);
        let value = secret(form.value);
        let id = form.id.trim().to_owned();
        let label = form.label.trim().to_owned();
        let targets = view::lines(&form.targets);
        let kind = view::ENTRY_KINDS.get(form.kind as usize).copied().unwrap_or("generic");
        let editing = form.editing;

        if id.is_empty() {
            store.set_form_error("Informe o identificador.".into());
            return;
        }
        if !editing && value.is_empty() {
            store.set_form_error("Informe o valor do segredo.".into());
            return;
        }

        store.set_form_error(SharedString::new());
        self.set_busy(true);
        background(
            &self.client,
            move |client| {
                if editing {
                    let label = (!label.is_empty()).then_some(label.as_str());
                    let value = (!value.is_empty()).then_some(value.as_str());
                    client.update_entry(&id, label, &targets, value, &passphrase)
                } else {
                    let label = if label.is_empty() { id.as_str() } else { label.as_str() };
                    client.register_entry(&id, kind, label, &targets, &value, &passphrase)
                }
            },
            move |c, result| {
                c.set_busy(false);
                match result {
                    Ok(entry) => {
                        c.store().invoke_close_modal();
                        let title = if editing { "Registro atualizado" } else { "Segredo cadastrado" };
                        c.toast("success", title, &format!("{} · revisão {}", entry.id, entry.revision));
                        c.refresh();
                    }
                    Err(error) => c.fail(&error),
                }
            },
        );
    }

    fn authorize(&mut self, form: AuthorizeForm) {
        let store = self.store();
        let passphrase = secret(form.passphrase.clone());
        let entry_id = self.entries.get(form.entry as usize).map(|e| e.id.clone()).unwrap_or_default();
        let request = view::build_authorize(&view::AuthorizeInput {
            id: &form.id,
            entry_id: &entry_id,
            description: &form.description,
            params: &form.params,
            action: form.action as usize,
            target: &form.target,
            method: form.method as usize,
            content_type: &form.content_type,
            body: &form.body,
            headers: &form.headers,
            result_fields: &form.result_fields,
            args: &form.args,
            env: &form.env,
            timeout: &form.timeout,
        });
        let request = match request {
            Ok(request) => request,
            Err(message) => {
                store.set_form_error(message.into());
                return;
            }
        };

        store.set_form_error(SharedString::new());
        self.set_busy(true);
        background(
            &self.client,
            move |client| client.authorize_operation(&request, &passphrase),
            |c, result| {
                c.set_busy(false);
                match result {
                    Ok(operation) => {
                        c.store().invoke_close_modal();
                        c.toast("success", "Operação autorizada", &format!("{} → {}", operation.id, operation.target));
                        c.refresh();
                    }
                    Err(error) => c.fail(&error),
                }
            },
        );
    }

    fn init_vault(&mut self, passphrase: SharedString, confirmation: SharedString, enable_totp: bool) {
        let passphrase = secret(passphrase);
        let confirmation = secret(confirmation);
        let store = self.store();
        if *passphrase != *confirmation {
            store.set_form_error("As senhas não conferem.".into());
            return;
        }
        if passphrase.chars().count() < 8 {
            store.set_form_error("Use pelo menos 8 caracteres; 12 ou mais é o recomendado.".into());
            return;
        }
        store.set_form_error(SharedString::new());
        self.set_busy(true);
        background(
            &self.client,
            move |client| client.init_vault(&passphrase, enable_totp),
            |c, result| {
                c.set_busy(false);
                match result {
                    Ok(outcome) => {
                        if let Some(uri) = outcome.totp_uri.filter(|u| !u.is_empty()) {
                            let store = c.store();
                            store.set_totp_qr(qr_image(&uri));
                            store.set_totp_uri(uri.as_str().into());
                        }
                        c.toast("success", "Cofre criado", "Agora cadastre o primeiro segredo.");
                        c.refresh();
                    }
                    Err(error) => c.fail(&error),
                }
            },
        );
    }

    fn finish_setup(&mut self) {
        let store = self.store();
        store.set_totp_uri(SharedString::new());
        store.set_totp_qr(Image::default());
        store.set_page(1);
        self.refresh();
    }

    fn filter_commands(&self, query: &str) {
        let rows: Vec<CommandItem> = commands()
            .into_iter()
            .filter(|c| view::matches(query, &[&c.title, &c.group]))
            .collect();
        self.commands_model.set_vec(rows);
    }
}

fn commands() -> Vec<CommandItem> {
    [
        ("go-approvals", "Ir para Aprovações", "Navegação", "Ctrl 1"),
        ("go-entries", "Ir para Registros", "Navegação", "Ctrl 2"),
        ("go-operations", "Ir para Operações", "Navegação", "Ctrl 3"),
        ("new-entry", "Cadastrar novo segredo", "Registros", "Ctrl N"),
        ("edit-entry", "Editar registro selecionado", "Registros", "Enter"),
        ("remove-entry", "Remover registro selecionado", "Registros", "Del"),
        ("authorize", "Autorizar nova operação", "Operações", ""),
        ("revoke", "Revogar operação selecionada", "Operações", "Del"),
        ("refresh", "Atualizar dados", "Geral", "F5"),
        ("shortcuts", "Ver atalhos de teclado", "Geral", "?"),
    ]
    .into_iter()
    .map(|(id, title, group, shortcut)| CommandItem {
        id: id.into(),
        title: title.into(),
        group: group.into(),
        shortcut: shortcut.into(),
    })
    .collect()
}

fn qr_image(uri: &str) -> Image {
    let Ok(code) = qrcode::QrCode::new(uri.as_bytes()) else { return Image::default() };
    let modules = code.width();
    let scale = 8;
    let size = (modules * scale) as u32;
    let colors = code.to_colors();
    let mut buffer = SharedPixelBuffer::<Rgba8Pixel>::new(size, size);
    let width = size as usize;
    for (index, pixel) in buffer.make_mut_slice().iter_mut().enumerate() {
        let (x, y) = (index % width / scale, index / width / scale);
        let dark = colors[y * modules + x] == qrcode::Color::Dark;
        let value = if dark { 0x0d } else { 0xff };
        *pixel = Rgba8Pixel { r: value, g: value, b: value + if dark { 6 } else { 0 }, a: 0xff };
    }
    Image::from_rgba8(buffer)
}

fn main() -> Result<(), slint::PlatformError> {
    let app = AppWindow::new()?;
    let store = app.global::<Store>();

    let entries_model = Rc::new(VecModel::default());
    let operations_model = Rc::new(VecModel::default());
    let approvals_model = Rc::new(VecModel::default());
    let toasts_model = Rc::new(VecModel::default());
    let commands_model = Rc::new(VecModel::from(commands()));
    store.set_entries(entries_model.clone().into());
    store.set_operations(operations_model.clone().into());
    store.set_approvals(approvals_model.clone().into());
    store.set_toasts(toasts_model.clone().into());
    store.set_commands(commands_model.clone().into());

    store.on_refresh(|| {
        with(|c| c.refresh());
    });
    store.on_filter_entries(|_| {
        with(|c| c.render_entries());
    });
    store.on_filter_operations(|_| {
        with(|c| c.render_operations());
    });
    store.on_approve(|request_id| {
        with(|c| c.approve(request_id));
    });
    store.on_confirm_submit(|passphrase| {
        with(|c| c.confirm(passphrase));
    });
    store.on_save_entry(|form| {
        with(|c| c.save_entry(form));
    });
    store.on_authorize(|form| {
        with(|c| c.authorize(form));
    });
    store.on_init_vault(|passphrase, confirmation, totp| {
        with(|c| c.init_vault(passphrase, confirmation, totp));
    });
    store.on_finish_setup(|| {
        with(|c| c.finish_setup());
    });
    store.on_dismiss_toast(|id| {
        with(|c| c.dismiss_toast(id));
    });
    store.on_palette_filter(|query| {
        with(|c| c.filter_commands(&query));
    });

    let controller = Controller {
        app: app.clone_strong(),
        client: BrokerClient::from_env(),
        health: Health::default(),
        entries: Vec::new(),
        operations: Vec::new(),
        approvals: Vec::new(),
        known_requests: HashSet::new(),
        first_snapshot: true,
        polling: false,
        toast_seq: 0,
        entries_model,
        operations_model,
        approvals_model,
        toasts_model,
        commands_model,
    };
    CONTROLLER.with(|cell| *cell.borrow_mut() = Some(controller));

    let poll_timer = Timer::default();
    poll_timer.start(TimerMode::Repeated, POLL_INTERVAL, || {
        with(|c| c.poll());
    });
    let tick_timer = Timer::default();
    tick_timer.start(TimerMode::Repeated, Duration::from_secs(1), || {
        with(|c| c.tick());
    });

    let weak = app.as_weak();
    Timer::single_shot(Duration::ZERO, move || {
        if let Some(app) = weak.upgrade() {
            chrome::apply_dark_title_bar(app.window());
        }
        with(|c| c.refresh());
    });

    app.run()?;
    CONTROLLER.with(|cell| cell.borrow_mut().take());
    Ok(())
}
