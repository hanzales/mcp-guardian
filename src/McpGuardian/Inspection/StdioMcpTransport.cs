using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace McpGuardian.Inspection;

public sealed class StdioMcpTransport : IMcpTransport
{
    private readonly Process process;
    private readonly InspectionLimits limits;
    private readonly Task stderrDrain;
    private int requestId;

    public StdioMcpTransport(ServerDefinition server, InspectionLimits limits)
    {
        if (!server.IsStdio)
        {
            throw new ArgumentException("A stdio transport requires a command.", nameof(server));
        }

        this.limits = limits;
        var startInfo = new ProcessStartInfo
        {
            FileName = server.Command!,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in server.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        foreach (var variable in server.Environment)
        {
            startInfo.Environment[variable.Key] = variable.Value;
        }

        process = Process.Start(startInfo) ?? throw new IOException($"Failed to start MCP server '{server.Name}'.");
        stderrDrain = DrainAsync(process.StandardError);
    }

    public string Name => "stdio";

    public async Task<JsonDocument> SendRequestAsync(string method, object? parameters, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(limits.Timeout);
        var id = Interlocked.Increment(ref requestId);
        await WriteAsync(new { jsonrpc = "2.0", id, method, @params = parameters ?? new { } }, timeout.Token);
        while (true)
        {
            var document = await ReadMessageAsync(timeout.Token);
            if (document.RootElement.TryGetProperty("id", out var responseId) && responseId.TryGetInt32(out var value) && value == id)
            {
                return document;
            }
            document.Dispose();
        }
    }

    public async Task SendNotificationAsync(string method, object? parameters, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(limits.Timeout);
        await WriteAsync(new { jsonrpc = "2.0", method, @params = parameters ?? new { } }, timeout.Token);
    }

    private async Task WriteAsync(object message, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(message);
        await process.StandardInput.WriteLineAsync(json.AsMemory(), cancellationToken);
        await process.StandardInput.FlushAsync(cancellationToken);
    }

    private async Task<JsonDocument> ReadMessageAsync(CancellationToken cancellationToken)
    {
        var line = await ReadBoundedLineAsync(process.StandardOutput, cancellationToken);
        if (line is null)
        {
            throw new IOException("The MCP stdio server closed its output before responding.");
        }
        return JsonDocument.Parse(line);
    }

    private async Task<string?> ReadBoundedLineAsync(TextReader reader, CancellationToken cancellationToken)
    {
        var value = new StringBuilder(Math.Min(limits.MaxResponseBytes, 4096));
        var character = new char[1];
        var byteCount = 0;
        while (true)
        {
            var read = await reader.ReadAsync(character, cancellationToken);
            if (read == 0) return value.Length == 0 ? null : value.ToString();
            if (character[0] == '\n') return value.ToString();
            if (character[0] == '\r') continue;
            value.Append(character[0]);
            byteCount += Encoding.UTF8.GetByteCount(character);
            if (byteCount > limits.MaxResponseBytes)
            {
                throw new InvalidDataException($"MCP response exceeded the {limits.MaxResponseBytes}-byte limit.");
            }
        }
    }

    private static async Task DrainAsync(TextReader reader)
    {
        var buffer = new char[4096];
        while (await reader.ReadAsync(buffer) > 0)
        {
            // Drain without retaining potentially sensitive server diagnostics.
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            process.StandardInput.Close();
            if (!process.HasExited)
            {
                process.Kill(true);
            }
            await process.WaitForExitAsync().WaitAsync(limits.Timeout);
            await stderrDrain.WaitAsync(limits.Timeout);
        }
        catch (Exception exception) when (exception is InvalidOperationException or TimeoutException or
                                          System.ComponentModel.Win32Exception or IOException)
        {
            // Cleanup is best effort after the process has been killed.
        }
        finally
        {
            process.Dispose();
        }
    }
}
