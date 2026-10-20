using System.Drawing;
using System.Windows.Forms;

namespace SVault.Manager;

internal static class Theme
{
    public static readonly Color Background = Color.FromArgb(24, 26, 31);
    public static readonly Color Surface = Color.FromArgb(32, 35, 42);
    public static readonly Color SurfaceAlt = Color.FromArgb(39, 43, 51);
    public static readonly Color Border = Color.FromArgb(55, 60, 70);
    public static readonly Color Text = Color.FromArgb(228, 231, 237);
    public static readonly Color TextMuted = Color.FromArgb(150, 157, 170);
    public static readonly Color Accent = Color.FromArgb(88, 166, 255);
    public static readonly Color Danger = Color.FromArgb(233, 96, 96);
    public static readonly Color Success = Color.FromArgb(88, 205, 144);
}

internal static class Ui
{
    public static Label Label(string text, int size = 9, bool muted = false)
    {
        return new Label
        {
            Text = text,
            AutoSize = true,
            ForeColor = muted ? Theme.TextMuted : Theme.Text,
            Font = new Font("Segoe UI", size, muted ? FontStyle.Regular : FontStyle.Regular)
        };
    }

    public static Label Heading(string text)
    {
        return new Label
        {
            Text = text,
            AutoSize = true,
            ForeColor = Theme.Text,
            Font = new Font("Segoe UI Semibold", 12, FontStyle.Bold)
        };
    }

    public static Button Primary(string text)
    {
        var button = new Button
        {
            Text = text,
            AutoSize = true,
            Padding = new Padding(12, 5, 12, 5),
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.Accent,
            ForeColor = Color.FromArgb(12, 16, 22),
            Font = new Font("Segoe UI Semibold", 9),
            Cursor = Cursors.Hand
        };
        button.FlatAppearance.BorderSize = 0;
        return button;
    }

    public static Button Secondary(string text)
    {
        var button = new Button
        {
            Text = text,
            AutoSize = true,
            Padding = new Padding(12, 5, 12, 5),
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.SurfaceAlt,
            ForeColor = Theme.Text,
            Font = new Font("Segoe UI", 9),
            Cursor = Cursors.Hand
        };
        button.FlatAppearance.BorderColor = Theme.Border;
        button.FlatAppearance.BorderSize = 1;
        return button;
    }

    public static Button Danger(string text)
    {
        var button = Secondary(text);
        button.ForeColor = Theme.Danger;
        return button;
    }

    public static TextBox Field(bool secret = false)
    {
        return new TextBox
        {
            UseSystemPasswordChar = secret,
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Theme.SurfaceAlt,
            ForeColor = Theme.Text,
            Width = 380
        };
    }

    public static ListView List(params string[] columns)
    {
        var list = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            HideSelection = false,
            GridLines = false,
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Theme.Surface,
            ForeColor = Theme.Text,
            Dock = DockStyle.Fill
        };

        foreach (var column in columns)
        {
            list.Columns.Add(column);
        }

        return list;
    }
}
