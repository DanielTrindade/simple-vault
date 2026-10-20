using System.Drawing;
using System.Windows.Forms;
using SVault.Client;
using SVault.Core.Protocol;

namespace SVault.Manager;

internal sealed class MainForm : Form
{
    private readonly BrokerClient _client = new();
    private readonly Label _status = Ui.Label("Iniciando...", 9, muted: true);
    private readonly ListView _entriesView = Ui.List("Identificador", "Tipo", "Alvos autorizados", "Atualizado");
    private readonly ListView _operationsView = Ui.List("Operacao", "Registro", "Acao", "Alvo");
    private readonly ListView _approvalsView = Ui.List("Solicitacao", "Operacao", "Registro", "Alvo", "Expira");
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 5000 };
    private bool _totpEnabled;
    private string? _lastRequestId;

    public MainForm()
    {
        Text = "SVault Manager";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(980, 620);
        ClientSize = new Size(1080, 680);
        BackColor = Theme.Background;
        ForeColor = Theme.Text;
        Font = new Font("Segoe UI", 9);

        var title = Ui.Heading("SVault Manager");
        title.Location = new Point(20, 18);

        var subtitle = Ui.Label("Cofre de credenciais isolado. Os agentes nunca recebem os valores.", 9, muted: true);
        subtitle.Location = new Point(20, 46);

        _status.Location = new Point(20, 70);
        _status.AutoSize = false;
        _status.Size = new Size(1040, 20);

        var tabs = new TabControl
        {
            Location = new Point(20, 100),
            Size = new Size(1040, 520),
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom
        };

        var entriesPage = BuildEntriesPage();
        var operationsPage = BuildOperationsPage();
        var approvalsPage = BuildApprovalsPage();

        tabs.TabPages.Add(entriesPage);
        tabs.TabPages.Add(operationsPage);
        tabs.TabPages.Add(approvalsPage);

        var footer = Ui.Label("Dica: use o svaultctl para automacoes. Os valores nunca sao exibidos, copiados ou salvos em arquivo temporario.", 9, muted: true);
        footer.Location = new Point(20, 634);
        footer.AutoSize = false;
        footer.Size = new Size(1040, 20);
        footer.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;

        Controls.AddRange(new Control[] { title, subtitle, _status, tabs, footer });

        _timer.Tick += async (_, _) => await SafeRefreshApprovals();
        _timer.Start();
        FormClosing += (_, _) => _timer.Stop();

        Shown += async (_, _) => await RefreshAll();
    }

    private TabPage BuildEntriesPage()
    {
        var page = new TabPage("Registros") { BackColor = Theme.Surface, ForeColor = Theme.Text, Padding = new Padding(12) };

        var add = Ui.Primary("Cadastrar segredo");
        add.Location = new Point(0, 0);
        add.Click += (_, _) => AddEntry();

        var update = Ui.Secondary("Atualizar");
        update.Location = new Point(140, 0);
        update.Click += (_, _) => UpdateEntry();

        var remove = Ui.Danger("Remover");
        remove.Location = new Point(230, 0);
        remove.Click += (_, _) => RemoveEntry();

        var refresh = Ui.Secondary("Atualizar lista");
        refresh.Location = new Point(320, 0);
        refresh.Click += async (_, _) => await RefreshEntries();

        var toolbar = new Panel { Location = new Point(0, 0), Size = new Size(1000, 40), BackColor = Theme.Surface };
        toolbar.Controls.AddRange(new Control[] { add, update, remove, refresh });

        _entriesView.Location = new Point(0, 46);
        _entriesView.Size = new Size(1000, 420);
        _entriesView.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;

        page.Controls.AddRange(new Control[] { toolbar, _entriesView });
        return page;
    }

    private TabPage BuildOperationsPage()
    {
        var page = new TabPage("Operacoes") { BackColor = Theme.Surface, ForeColor = Theme.Text, Padding = new Padding(12) };

        var authorize = Ui.Primary("Autorizar operacao");
        authorize.Location = new Point(0, 0);
        authorize.Click += (_, _) => AuthorizeOperation();

        var revoke = Ui.Danger("Revogar");
        revoke.Location = new Point(140, 0);
        revoke.Click += (_, _) => RevokeOperation();

        var refresh = Ui.Secondary("Atualizar lista");
        refresh.Location = new Point(230, 0);
        refresh.Click += async (_, _) => await RefreshOperations();

        var toolbar = new Panel { Location = new Point(0, 0), Size = new Size(1000, 40), BackColor = Theme.Surface };
        toolbar.Controls.AddRange(new Control[] { authorize, revoke, refresh });

        _operationsView.Location = new Point(0, 46);
        _operationsView.Size = new Size(1000, 420);
        _operationsView.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;

        page.Controls.AddRange(new Control[] { toolbar, _operationsView });
        return page;
    }

    private TabPage BuildApprovalsPage()
    {
        var page = new TabPage("Aprovacoes") { BackColor = Theme.Surface, ForeColor = Theme.Text, Padding = new Padding(12) };

        var approve = Ui.Primary("Aprovar e executar");
        approve.Location = new Point(0, 0);
        approve.Click += (_, _) => ApproveSelected();

        var reject = Ui.Danger("Rejeitar");
        reject.Location = new Point(140, 0);
        reject.Click += (_, _) => RejectSelected();

        var refresh = Ui.Secondary("Atualizar lista");
        refresh.Location = new Point(230, 0);
        refresh.Click += async (_, _) => await SafeRefreshApprovals();

        var toolbar = new Panel { Location = new Point(0, 0), Size = new Size(1000, 40), BackColor = Theme.Surface };
        toolbar.Controls.AddRange(new Control[] { approve, reject, refresh });

        _approvalsView.Location = new Point(0, 46);
        _approvalsView.Size = new Size(1000, 420);
        _approvalsView.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;

        page.Controls.AddRange(new Control[] { toolbar, _approvalsView });
        return page;
    }

    private async Task RefreshAll()
    {
        try
        {
            var health = await _client.HealthAsync();
            _totpEnabled = health.TotpRequired;
            _status.Text = health.VaultInitialized
                ? $"Broker ativo em {health.ServiceIdentity} | cofre inicializado | TOTP {(health.TotpRequired ? "ativo" : "inativo")} | {health.EntryCount} registro(s) | {health.OperationCount} operacao(oes)"
                : $"Broker ativo em {health.ServiceIdentity} | cofre ainda nao inicializado (use svaultctl init)";
            _status.ForeColor = health.VaultInitialized ? Theme.Text : Theme.Accent;
        }
        catch (Exception ex)
        {
            _status.Text = "Broker indisponivel: " + ex.Message;
            _status.ForeColor = Theme.Danger;
        }

        await RefreshEntries();
        await RefreshOperations();
        await SafeRefreshApprovals();
    }

    private async Task RefreshEntries()
    {
        try
        {
            var entries = await _client.ListEntriesAsync();
            _entriesView.Items.Clear();
            foreach (var entry in entries.Entries)
            {
                var item = new ListViewItem(entry.Id);
                item.SubItems.Add(entry.Kind);
                item.SubItems.Add(string.Join(", ", entry.Targets));
                item.SubItems.Add(entry.UpdatedAt);
                item.Tag = entry.Id;
                _entriesView.Items.Add(item);
            }
        }
        catch (Exception ex)
        {
            _status.Text = "Falha ao listar registros: " + ex.Message;
        }
    }

    private async Task RefreshOperations()
    {
        try
        {
            var operations = await _client.ListOperationsAsync();
            _operationsView.Items.Clear();
            foreach (var operation in operations.Operations)
            {
                var item = new ListViewItem(operation.Id);
                item.SubItems.Add(operation.EntryId);
                item.SubItems.Add(operation.Action);
                item.SubItems.Add(operation.Target);
                item.Tag = operation.Id;
                _operationsView.Items.Add(item);
            }
        }
        catch (Exception ex)
        {
            _status.Text = "Falha ao listar operacoes: " + ex.Message;
        }
    }

    private async Task SafeRefreshApprovals()
    {
        try
        {
            var pending = await _client.PendingApprovalsAsync();
            var known = new HashSet<string>(StringComparer.Ordinal);

            foreach (var request in pending.Requests)
            {
                known.Add(request.RequestId);
                var existing = _approvalsView.Items.Cast<ListViewItem>()
                    .FirstOrDefault(i => i.Tag as string == request.RequestId);

                if (existing is null)
                {
                    var item = new ListViewItem(request.RequestId);
                    item.SubItems.Add(request.Summary.OperationId);
                    item.SubItems.Add(request.Summary.EntryId);
                    item.SubItems.Add(request.Summary.Target);
                    item.SubItems.Add(request.ExpiresAt);
                    item.Tag = request.RequestId;
                    _approvalsView.Items.Add(item);

                    if (_lastRequestId != request.RequestId)
                    {
                        _lastRequestId = request.RequestId;
                        NotifyRequest(request);
                    }
                }
            }

            foreach (var item in _approvalsView.Items.Cast<ListViewItem>().ToList())
            {
                if (item.Tag is string id && !known.Contains(id))
                {
                    _approvalsView.Items.Remove(item);
                }
            }
        }
        catch
        {
            // the status bar already reports broker availability
        }
    }

    private void NotifyRequest(PendingRequest request)
    {
        _status.Text = $"Nova solicitacao: {request.Summary.OperationId} usando {request.Summary.EntryId} em {request.Summary.Target}";
        _status.ForeColor = Theme.Accent;
    }

    private async void AddEntry()
    {
        try
        {
            using var dialog = new EntryDialog(editing: false);
            if (dialog.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            using var prompt = new SecretPromptDialog(
                "Cadastrar segredo",
                $"O registro {dialog.EntryId} sera gravado no cofre do broker.",
                _totpEnabled);

            if (prompt.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            var entry = await _client.RegisterEntryAsync(
                dialog.EntryId,
                dialog.Kind,
                dialog.Label,
                dialog.Targets,
                dialog.Value,
                prompt.Passphrase);

            _status.Text = $"Registro {entry.Id} cadastrado.";
            _status.ForeColor = Theme.Success;
            await RefreshEntries();
        }
        catch (BrokerCallException ex)
        {
            ShowError(ex.Message);
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
    }

    private async void UpdateEntry()
    {
        var id = SelectedId(_entriesView);
        if (id is null)
        {
            return;
        }

        try
        {
            using var dialog = new EntryDialog(editing: true);
            dialog.Text = "Atualizar registro " + id;
            if (dialog.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            using var prompt = new SecretPromptDialog(
                "Atualizar segredo",
                $"Confirmacao para alterar o registro {id}.",
                _totpEnabled);

            if (prompt.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            var value = string.IsNullOrEmpty(dialog.Value) ? null : dialog.Value;
            var entry = await _client.UpdateEntryAsync(id, value, null, dialog.Targets, prompt.Passphrase);
            _status.Text = $"Registro {entry.Id} atualizado (revisao {entry.Revision}).";
            _status.ForeColor = Theme.Success;
            await RefreshEntries();
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
    }

    private async void RemoveEntry()
    {
        var id = SelectedId(_entriesView);
        if (id is null)
        {
            return;
        }

        try
        {
            using var prompt = new SecretPromptDialog(
                "Remover segredo",
                $"O registro {id} e as operacoes que o usam serao removidos definitivamente.",
                _totpEnabled);

            if (prompt.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            await _client.DeleteEntryAsync(id, prompt.Passphrase);
            _status.Text = $"Registro {id} removido.";
            _status.ForeColor = Theme.Success;
            await RefreshEntries();
            await RefreshOperations();
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
    }

    private async void AuthorizeOperation()
    {
        try
        {
            var entries = (await _client.ListEntriesAsync()).Entries;
            if (entries.Count == 0)
            {
                ShowError("Cadastre um segredo antes de autorizar uma operacao.");
                return;
            }

            using var dialog = new AuthorizeDialog(entries);
            if (dialog.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            using var prompt = new SecretPromptDialog(
                "Autorizar operacao",
                $"A operacao {dialog.OperationId} podera usar {dialog.EntryId} em {dialog.Target}.",
                _totpEnabled);

            if (prompt.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            object? spec = dialog.Http is not null
                ? new
                {
                    method = dialog.Http.Method,
                    url = dialog.Http.Url,
                    contentType = dialog.Http.ContentType,
                    bodyFields = dialog.Http.BodyFields,
                    headers = dialog.Http.Headers,
                    resultFields = dialog.Http.ResultFields
                }
                : dialog.Process is not null
                    ? new
                    {
                        executable = dialog.Process.Executable,
                        args = dialog.Process.Args,
                        env = dialog.Process.Env,
                        timeoutSeconds = dialog.Process.TimeoutSeconds
                    }
                    : null;

            var operation = await _client.AuthorizeOperationAsync(
                dialog.OperationId,
                dialog.EntryId,
                dialog.Action,
                dialog.Target,
                dialog.Description,
                dialog.ParamNames,
                prompt.Passphrase,
                spec);

            _status.Text = $"Operacao {operation.Id} autorizada.";
            _status.ForeColor = Theme.Success;
            await RefreshOperations();
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
    }

    private async void RevokeOperation()
    {
        var id = SelectedId(_operationsView);
        if (id is null)
        {
            return;
        }

        try
        {
            using var prompt = new SecretPromptDialog(
                "Revogar operacao",
                $"A operacao {id} deixara de poder usar o segredo.",
                _totpEnabled);

            if (prompt.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            await _client.RevokeOperationAsync(id, prompt.Passphrase);
            _status.Text = $"Operacao {id} revogada.";
            _status.ForeColor = Theme.Success;
            await RefreshOperations();
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
    }

    private async void ApproveSelected()
    {
        var requestId = SelectedId(_approvalsView);
        if (requestId is null)
        {
            return;
        }

        try
        {
            using var prompt = new SecretPromptDialog(
                "Aprovar operacao",
                $"Digite a senha do cofre para autorizar a execucao e{( _totpEnabled ? " o codigo TOTP" : string.Empty)}.",
                _totpEnabled);

            if (prompt.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            var result = await _client.ApproveAsync(requestId, prompt.Passphrase, prompt.Totp);
            _status.Text = $"Solicitacao {requestId}: {result.Status}.";
            _status.ForeColor = result.Status == OperationStatuses.Completed ? Theme.Success : Theme.Danger;

            if (result.Result is not null)
            {
                ShowResult(requestId, result);
            }
            else if (result.Error is not null)
            {
                ShowError(result.Error);
            }

            await SafeRefreshApprovals();
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
    }

    private async void RejectSelected()
    {
        var requestId = SelectedId(_approvalsView);
        if (requestId is null)
        {
            return;
        }

        try
        {
            using var prompt = new SecretPromptDialog(
                "Rejeitar solicitacao",
                $"A solicitacao {requestId} sera descartada.",
                _totpEnabled);

            if (prompt.ShowDialog(this) != DialogResult.OK)
            {
                return;
            }

            await _client.RejectAsync(requestId, prompt.Passphrase);
            _status.Text = $"Solicitacao {requestId} rejeitada.";
            _status.ForeColor = Theme.TextMuted;
            await SafeRefreshApprovals();
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
    }

    private void ShowResult(string requestId, OkResult result)
    {
        var outcome = result.Result!;
        var body = outcome.Body ?? outcome.Output ?? string.Empty;

        using var dialog = new Form
        {
            Text = "Resultado sanitizado",
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedSingle,
            MinimizeBox = false,
            MaximizeBox = false,
            ShowInTaskbar = false,
            BackColor = Theme.Surface,
            ForeColor = Theme.Text,
            ClientSize = new Size(720, 420)
        };

        var heading = Ui.Heading("Resultado sanitizado");
        heading.Location = new Point(20, 18);

        var info = Ui.Label(
            $"Solicitacao {requestId} | tipo {outcome.Kind} | ok {outcome.Ok} | {outcome.DurationMs} ms",
            9,
            muted: true);
        info.Location = new Point(20, 46);

        var text = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Location = new Point(20, 74),
            Size = new Size(680, 300),
            BackColor = Theme.SurfaceAlt,
            ForeColor = Theme.Text,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Consolas", 9)
        };
        text.Text = body;

        var close = Ui.Primary("Fechar");
        close.Location = new Point(590, 382);
        close.Click += (_, _) => dialog.Close();

        dialog.Controls.AddRange(new Control[] { heading, info, text, close });
        dialog.ShowDialog(this);
    }

    private static string? SelectedId(ListView view)
    {
        if (view.SelectedItems.Count == 0)
        {
            return null;
        }

        return view.SelectedItems[0].Tag as string;
    }

    private void ShowError(string message)
    {
        _status.Text = message;
        _status.ForeColor = Theme.Danger;
        MessageBox.Show(this, message, "SVault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }
}

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }
}
