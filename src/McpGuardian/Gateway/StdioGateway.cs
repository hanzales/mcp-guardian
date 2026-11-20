using System.Diagnostics;
using System.Text;
using System.Text.Json;
using McpGuardian.Inspection;

namespace McpGuardian.Gateway;

public sealed class StdioGateway
{
    public async Task<int> RunAsync(ServerDefinition server, GatewayPolicy policy, string auditPath, TextReader input, TextWriter output, CancellationToken cancellationToken = default)
    {
        if (!server.IsStdio) throw new InvalidDataException("The runtime gateway currently supports stdio servers only.");
        var start = new ProcessStartInfo { FileName = server.Command!, UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (var argument in server.Arguments) start.ArgumentList.Add(argument);
        foreach (var variable in server.Environment) start.Environment[variable.Key] = variable.Value;
        using var process = Process.Start(start) ?? throw new IOException("Failed to start the protected MCP server.");
        var stderr = DrainAsync(process.StandardError);
        using var audit = new AuditChainWriter(auditPath);
        var engine = new PolicyEngine(policy);
        try
        {
            string? line;
            while ((line = await input.ReadLineAsync(cancellationToken)) is not null)
            {
                if (Encoding.UTF8.GetByteCount(line) > policy.Limits.MaxRequestBytes) throw new InvalidDataException("Gateway request size limit exceeded.");
                using var request = JsonDocument.Parse(line);
                var root = request.RootElement;
                if (root.TryGetProperty("method", out var method) && method.GetString() == "tools/call" && root.TryGetProperty("params", out var parameters))
                {
                    var tool = parameters.TryGetProperty("name", out var name) ? name.GetString() ?? "<unnamed>" : "<unnamed>";
                    var arguments = parameters.TryGetProperty("arguments", out var args) ? args : JsonSerializer.SerializeToElement(new { });
                    var decision = engine.Evaluate(server.Name, tool, arguments, DateTimeOffset.UtcNow);
                    audit.Write(server.Name, tool, decision, arguments);
                    if (!decision.Allowed)
                    {
                        if (root.TryGetProperty("id", out var id))
                        {
                            await output.WriteLineAsync(JsonSerializer.Serialize(new { jsonrpc = "2.0", id = id.Clone(), error = new { code = decision.ApprovalRequired ? -32001 : -32003, message = decision.Reason } }));
                            await output.FlushAsync(cancellationToken);
                        }
                        continue;
                    }
                }

                await process.StandardInput.WriteLineAsync(line.AsMemory(), cancellationToken);
                await process.StandardInput.FlushAsync(cancellationToken);
                if (!root.TryGetProperty("id", out var expectedId)) continue;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(policy.Limits.TimeoutSeconds));
                while (true)
                {
                    var response = await process.StandardOutput.ReadLineAsync(timeout.Token) ?? throw new IOException("Protected MCP server closed its output.");
                    if (Encoding.UTF8.GetByteCount(response) > policy.Limits.MaxResponseBytes) throw new InvalidDataException("Gateway response size limit exceeded.");
                    await output.WriteLineAsync(response);
                    await output.FlushAsync(timeout.Token);
                    using var message = JsonDocument.Parse(response);
                    if (message.RootElement.TryGetProperty("id", out var actualId) && actualId.ToString() == expectedId.ToString()) break;
                }
            }
            return 0;
        }
        finally
        {
            try { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); await stderr; }
            catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or IOException) { }
        }
    }

    private static async Task DrainAsync(TextReader reader)
    {
        var buffer = new char[4096];
        while (await reader.ReadAsync(buffer) > 0) { }
    }
}
