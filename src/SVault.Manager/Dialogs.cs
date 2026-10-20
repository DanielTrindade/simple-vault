using System.Drawing;
using System.Windows.Forms;
using SVault.Client;
using SVault.Core.Protocol;

namespace SVault.Manager;

internal sealed class SecretPromptDialog : Form
{
    private readonly TextBox _passphrase = Ui.Field(secret: true);
    private readonly TextBox _totp = Ui.Field();

    public SecretPromptDialog(string title, string description, bool requestTotp)
    {
        Text = title;
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MinimizeBox = false;
        MaximizeBox = false;
        ShowInTaskbar = false;
        BackColor = Theme.Surface;
        ForeColor = Theme.Text;
        ClientSize = new Size(430, requestTotp ? 210 : 165);
        FormBorderStyle = FormBorderStyle.FixedSingle;

        var heading = Ui.Heading(title);
        heading.Location = new Point(20, 18);

        var message = Ui.Label(description, 9, muted: true);
        message.Location = new Point(20, 48);
        message.AutoSize = false;
        message.Size = new Size(390, 34);

        var passLabel = Ui.Label("Senha do cofre");
        passLabel.Location = new Point(20, 92);

        _passphrase.Location = new Point(20, 112);
        _passphrase.Width = 390;

        var totpLabel = Ui.Label("Codigo TOTP (6 digitos)");
        totpLabel.Location = new Point(20, 142);
        totpLabel.Visible = requestTotp;

        _totp.Location = new Point(20, 162);
        _totp.Width = 390;
        _totp.Visible = requestTotp;
        _totp.MaxLength = 8;

        var confirm = Ui.Primary("Confirmar");
        confirm.Location = new Point(232, 130);
        confirm.Click += (_, _) => DialogResult = DialogResult.OK;

        var cancel = Ui.Secondary("Cancelar");
        cancel.Location = new Point(150, 130);
        cancel.Click += (_, _) => DialogResult = DialogResult.Cancel;

        Controls.AddRange(new Control[] { heading, message, passLabel, _passphrase, totpLabel, _totp, confirm, cancel });
        AcceptButton = confirm;
        CancelButton = cancel;
    }

    public string Passphrase => _passphrase.Text;

    public string? Totp => string.IsNullOrWhiteSpace(_totp.Text) ? null : _totp.Text.Trim();
}

internal sealed class EntryDialog : Form
{
    private readonly TextBox _id = Ui.Field();
    private readonly TextBox _label = Ui.Field();
    private readonly ComboBox _kind = new();
    private readonly TextBox _targets = Ui.Field();
    private readonly TextBox _value = Ui.Field(secret: true);
    private readonly bool _editing;

    public EntryDialog(bool editing)
    {
        _editing = editing;
        Text = editing ? "Atualizar segredo" : "Cadastrar segredo";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MinimizeBox = false;
        MaximizeBox = false;
        ShowInTaskbar = false;
        BackColor = Theme.Surface;
        ForeColor = Theme.Text;
        ClientSize = new Size(430, 400);

        var kindLabel = Ui.Label("Tipo");
        kindLabel.Location = new Point(20, 20);
        _kind.DropDownStyle = ComboBoxStyle.DropDownList;
        _kind.Location = new Point(20, 40);
        _kind.Width = 390;
        _kind.Items.AddRange(new object[] { "cpf", "password", "token", "generic" });
        _kind.SelectedIndex = 3;

        var idLabel = Ui.Label("Identificador (visivel para os agentes)");
        idLabel.Location = new Point(20, 72);
        _id.Location = new Point(20, 92);
        _id.Width = 390;
        _id.Enabled = !editing;

        var labelLabel = Ui.Label("Rotulo");
        labelLabel.Location = new Point(20, 124);
        _label.Location = new Point(20, 144);
        _label.Width = 390;

        var targetsLabel = Ui.Label("Alvos autorizados (um por linha: dominio/URL ou caminho do executavel)");
        targetsLabel.Location = new Point(20, 176);
        _targets.Location = new Point(20, 196);
        _targets.Width = 390;
        _targets.Height = 60;
        _targets.Multiline = true;
        _targets.ScrollBars = ScrollBars.Vertical;

        var valueLabel = Ui.Label(editing ? "Novo valor (deixe vazio para manter)" : "Valor do segredo");
        valueLabel.Location = new Point(20, 266);
        _value.Location = new Point(20, 286);
        _value.Width = 390;

        var hint = Ui.Label("O valor e enviado diretamente ao broker, sem eco, sem area de transferencia e sem arquivo temporario.", 9, muted: true);
        hint.Location = new Point(20, 318);
        hint.AutoSize = false;
        hint.Size = new Size(390, 34);

        var confirm = Ui.Primary("Salvar");
        confirm.Location = new Point(232, 350);
        confirm.Click += (_, _) => Save();

        var cancel = Ui.Secondary("Cancelar");
        cancel.Location = new Point(150, 350);
        cancel.Click += (_, _) => DialogResult = DialogResult.Cancel;

        Controls.AddRange(new Control[]
        {
            kindLabel, _kind, idLabel, _id, labelLabel, _label, targetsLabel, _targets,
            valueLabel, _value, hint, confirm, cancel
        });
        AcceptButton = confirm;
        CancelButton = cancel;
    }

    public string EntryId => _id.Text.Trim();

    public string Kind => _kind.SelectedItem?.ToString() ?? "generic";

    public string Label => string.IsNullOrWhiteSpace(_label.Text) ? EntryId : _label.Text.Trim();

    public IReadOnlyList<string> Targets => _targets.Text
        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public string Value => _value.Text;

    private void Save()
    {
        if (string.IsNullOrWhiteSpace(_id.Text))
        {
            MessageBox.Show(this, "Informe o identificador.", "SVault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (!_editing && string.IsNullOrEmpty(_value.Text))
        {
            MessageBox.Show(this, "Informe o valor do segredo.", "SVault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        DialogResult = DialogResult.OK;
    }
}

internal sealed class AuthorizeDialog : Form
{
    private readonly TextBox _id = Ui.Field();
    private readonly ComboBox _entry = new();
    private readonly ComboBox _action = new();
    private readonly TextBox _target = Ui.Field();
    private readonly TextBox _description = Ui.Field();
    private readonly TextBox _params = Ui.Field();
    private readonly TextBox _method = Ui.Field();
    private readonly TextBox _contentType = Ui.Field();
    private readonly TextBox _body = Ui.Field();
    private readonly TextBox _headers = Ui.Field();
    private readonly TextBox _resultFields = Ui.Field();
    private readonly TextBox _executable = Ui.Field();
    private readonly TextBox _args = Ui.Field();
    private readonly TextBox _env = Ui.Field();
    private readonly TextBox _timeout = Ui.Field();
    private readonly Panel _httpPanel = new();
    private readonly Panel _processPanel = new();

    public AuthorizeDialog(IReadOnlyList<EntryMetadata> entries)
    {
        Text = "Autorizar operacao";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MinimizeBox = false;
        MaximizeBox = false;
        ShowInTaskbar = false;
        BackColor = Theme.Surface;
        ForeColor = Theme.Text;
        ClientSize = new Size(470, 620);

        var idLabel = Ui.Label("Identificador da operacao");
        idLabel.Location = new Point(20, 18);
        _id.Location = new Point(20, 38);
        _id.Width = 430;

        var entryLabel = Ui.Label("Registro (segredo) utilizado");
        entryLabel.Location = new Point(20, 68);
        _entry.DropDownStyle = ComboBoxStyle.DropDownList;
        _entry.Location = new Point(20, 88);
        _entry.Width = 430;
        foreach (var item in entries)
        {
            _entry.Items.Add(new ComboItem(item.Id, item.Id));
        }

        if (_entry.Items.Count > 0)
        {
            _entry.SelectedIndex = 0;
        }

        var actionLabel = Ui.Label("Acao");
        actionLabel.Location = new Point(20, 118);
        _action.DropDownStyle = ComboBoxStyle.DropDownList;
        _action.Location = new Point(20, 138);
        _action.Width = 430;
        _action.Items.AddRange(new object[] { "http.request", "noop.echo" });
        _action.SelectedIndex = 0;
        _action.SelectedIndexChanged += (_, _) => TogglePanels();

        var targetLabel = Ui.Label("Alvo (URL ou executavel) - precisa estar autorizado no registro");
        targetLabel.Location = new Point(20, 168);
        _target.Location = new Point(20, 188);
        _target.Width = 430;

        var descriptionLabel = Ui.Label("Descricao (opcional)");
        descriptionLabel.Location = new Point(20, 218);
        _description.Location = new Point(20, 238);
        _description.Width = 430;

        var paramsLabel = Ui.Label("Parametros que o agente pode preencher (separados por virgula)");
        paramsLabel.Location = new Point(20, 268);
        _params.Location = new Point(20, 288);
        _params.Width = 430;

        _httpPanel.Location = new Point(20, 318);
        _httpPanel.Size = new Size(430, 235);
        _httpPanel.BackColor = Theme.Surface;
        BuildHttpPanel();
        _httpPanel.Visible = true;

        _processPanel.Location = new Point(20, 318);
        _processPanel.Size = new Size(430, 110);
        _processPanel.BackColor = Theme.Surface;
        BuildProcessPanel();
        _processPanel.Visible = false;

        var confirm = Ui.Primary("Autorizar");
        confirm.Location = new Point(272, 562);
        confirm.Click += (_, _) => Save();

        var cancel = Ui.Secondary("Cancelar");
        cancel.Location = new Point(190, 562);
        cancel.Click += (_, _) => DialogResult = DialogResult.Cancel;

        Controls.AddRange(new Control[]
        {
            idLabel, _id, entryLabel, _entry, actionLabel, _action, targetLabel, _target,
            descriptionLabel, _description, paramsLabel, _params, _httpPanel, _processPanel, confirm, cancel
        });
        AcceptButton = confirm;
        CancelButton = cancel;
    }

    public string OperationId => _id.Text.Trim();

    public string EntryId => (_entry.SelectedItem as ComboItem)?.Value ?? string.Empty;

    public string Action => _action.SelectedItem?.ToString() ?? "http.request";

    public string Target => _target.Text.Trim();

    public string Description => _description.Text.Trim();

    public IReadOnlyList<string> ParamNames => _params.Text
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public HttpSpec? Http => Action == "http.request"
        ? new HttpSpec
        {
            Method = string.IsNullOrWhiteSpace(_method.Text) ? "POST" : _method.Text.Trim(),
            Url = Target,
            ContentType = string.IsNullOrWhiteSpace(_contentType.Text) ? "application/json" : _contentType.Text.Trim(),
            BodyFields = ParseMap(_body.Text),
            Headers = ParseMap(_headers.Text),
            ResultFields = _resultFields.Text
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList()
        }
        : null;

    public ProcessSpec? Process => Action == "process.stdin"
        ? new ProcessSpec
        {
            Executable = Target,
            Args = _args.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList(),
            Env = _env.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList(),
            TimeoutSeconds = int.TryParse(_timeout.Text, out var timeout) ? timeout : 30
        }
        : null;

    private void BuildHttpPanel()
    {
        var methodLabel = Ui.Label("Metodo");
        methodLabel.Location = new Point(0, 0);
        _method.Location = new Point(0, 18);
        _method.Width = 80;
        _method.Text = "POST";

        var contentLabel = Ui.Label("Content-Type");
        contentLabel.Location = new Point(92, 0);
        _contentType.Location = new Point(92, 18);
        _contentType.Width = 140;
        _contentType.Text = "application/json";

        var bodyLabel = Ui.Label("Corpo (campo=valor, um por linha; use {{secret}} e {{param:NOME}})");
        bodyLabel.Location = new Point(0, 46);
        _body.Location = new Point(0, 64);
        _body.Width = 430;
        _body.Height = 48;
        _body.Multiline = true;
        _body.ScrollBars = ScrollBars.Vertical;
        _body.Text = "password={{secret}}";

        var headersLabel = Ui.Label("Cabecalhos (nome=valor, um por linha)");
        headersLabel.Location = new Point(0, 119);
        _headers.Location = new Point(0, 137);
        _headers.Width = 430;
        _headers.Height = 48;
        _headers.Multiline = true;
        _headers.ScrollBars = ScrollBars.Vertical;

        var resultLabel = Ui.Label("Campos de retorno (JSON, separados por virgula)");
        resultLabel.Location = new Point(0, 190);
        _resultFields.Location = new Point(0, 208);
        _resultFields.Width = 430;

        _httpPanel.Controls.AddRange(new Control[]
        {
            methodLabel, _method, contentLabel, _contentType, bodyLabel, _body,
            headersLabel, _headers, resultLabel, _resultFields
        });
    }

    private void BuildProcessPanel()
    {
        var exeLabel = Ui.Label("Executavel fixo (o segredo vai por stdin, nunca por argumento)");
        exeLabel.Location = new Point(0, 0);
        _executable.Location = new Point(0, 18);
        _executable.Width = 430;

        var argsLabel = Ui.Label("Argumentos fixos (um por linha)");
        argsLabel.Location = new Point(0, 46);
        _args.Location = new Point(0, 64);
        _args.Width = 300;
        _args.Height = 40;
        _args.Multiline = true;

        var envLabel = Ui.Label("Variaveis fixas (NOME=VALOR)");
        envLabel.Location = new Point(310, 46);
        _env.Location = new Point(310, 64);
        _env.Width = 120;
        _env.Height = 40;
        _env.Multiline = true;

        var timeoutLabel = Ui.Label("Timeout (s)");
        timeoutLabel.Location = new Point(310, 18);
        _timeout.Location = new Point(375, 18);
        _timeout.Width = 55;
        _timeout.Text = "30";

        _processPanel.Controls.AddRange(new Control[]
        {
            exeLabel, _executable, argsLabel, _args, envLabel, _env, timeoutLabel, _timeout
        });
    }

    private void TogglePanels()
    {
        _httpPanel.Visible = Action == "http.request";
        _processPanel.Visible = Action == "process.stdin";
    }

    private void Save()
    {
        if (string.IsNullOrWhiteSpace(_id.Text) || string.IsNullOrWhiteSpace(_target.Text))
        {
            MessageBox.Show(this, "Informe o identificador e o alvo.", "SVault", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (Action == "process.stdin")
        {
            _executable.Text = Target;
        }

        DialogResult = DialogResult.OK;
    }

    private static Dictionary<string, string> ParseMap(string value)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in value.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = pair.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            map[pair[..separator].Trim()] = pair[(separator + 1)..].Trim();
        }

        return map;
    }
}

internal sealed class ComboItem
{
    public ComboItem(string text, string value)
    {
        Text = text;
        Value = value;
    }

    public string Text { get; }

    public string Value { get; }

    public override string ToString() => Text;
}

internal sealed class HttpSpec
{
    public string Method { get; init; } = "POST";
    public string Url { get; init; } = string.Empty;
    public string ContentType { get; init; } = "application/json";
    public Dictionary<string, string> BodyFields { get; init; } = new();
    public Dictionary<string, string> Headers { get; init; } = new();
    public List<string> ResultFields { get; init; } = new();
}

internal sealed class ProcessSpec
{
    public string Executable { get; init; } = string.Empty;
    public List<string> Args { get; init; } = new();
    public List<string> Env { get; init; } = new();
    public int TimeoutSeconds { get; init; } = 30;
}
