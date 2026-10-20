using System.Text;

namespace SVault.Client;

/// <summary>
/// Reads secrets from the console without echo and without ever touching the clipboard.
/// </summary>
public static class SecureInput
{
    public static string ReadSecret(string prompt)
    {
        Console.Write(prompt);
        Console.Out.Flush();

        var builder = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return builder.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (builder.Length > 0)
                {
                    builder.Length--;
                    Console.Write("\b \b");
                }

                continue;
            }

            if (key.Key == ConsoleKey.Escape)
            {
                Console.WriteLine();
                return string.Empty;
            }

            if (!char.IsControl(key.KeyChar))
            {
                builder.Append(key.KeyChar);
                Console.Write("*");
            }
        }
    }

    public static string ReadLine(string prompt)
    {
        Console.Write(prompt);
        Console.Out.Flush();
        var value = Console.ReadLine() ?? string.Empty;
        return value.Trim();
    }
}
