using System.Text.Json;

namespace McpGuardian.Inspection;

public interface IMcpTransport : IAsyncDisposable
{
    string Name { get; }
    Task<JsonDocument> SendRequestAsync(string method, object? parameters, CancellationToken cancellationToken);
    Task SendNotificationAsync(string method, object? parameters, CancellationToken cancellationToken);
}
