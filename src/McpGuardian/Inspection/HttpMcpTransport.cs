using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace McpGuardian.Inspection;

public sealed class HttpMcpTransport : IMcpTransport
{
    private readonly HttpClient client;
    private readonly Uri endpoint;
    private readonly InspectionLimits limits;
    private readonly IReadOnlyDictionary<string, string> headers;
    private string? sessionId;
    private string? protocolVersion;
    private int requestId;

    public HttpMcpTransport(ServerDefinition server, InspectionLimits limits, HttpMessageHandler? handler = null)
    {
        endpoint = server.Url ?? throw new ArgumentException("An HTTP transport requires a URL.", nameof(server));
        this.limits = limits;
        headers = server.Headers;
        client = handler is null
            ? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }, true)
            : new HttpClient(handler, false);
        client.Timeout = Timeout.InfiniteTimeSpan;
    }

    public string Name => "streamable-http";

    public async Task<JsonDocument> SendRequestAsync(string method, object? parameters, CancellationToken cancellationToken)
    {
        var id = Interlocked.Increment(ref requestId);
        var message = new { jsonrpc = "2.0", id, method, @params = parameters ?? new { } };
        using var response = await PostAsync(message, cancellationToken);
        var document = await ReadDocumentAsync(response, cancellationToken);
        if (method == "initialize" && document.RootElement.TryGetProperty("result", out var result) &&
            result.TryGetProperty("protocolVersion", out var version))
        {
            protocolVersion = version.GetString();
        }
        return document;
    }

    public async Task SendNotificationAsync(string method, object? parameters, CancellationToken cancellationToken)
    {
        var message = new { jsonrpc = "2.0", method, @params = parameters ?? new { } };
        using var response = await PostAsync(message, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"MCP notification failed with HTTP {(int)response.StatusCode}.");
        }
    }

    private async Task<HttpResponseMessage> PostAsync(object message, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(limits.Timeout);
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(JsonSerializer.Serialize(message), Encoding.UTF8, "application/json")
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        if (sessionId is not null) request.Headers.TryAddWithoutValidation("Mcp-Session-Id", sessionId);
        if (protocolVersion is not null) request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", protocolVersion);
        foreach (var header in headers)
        {
            if (!header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase) &&
                !header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (!response.IsSuccessStatusCode)
        {
            response.Dispose();
            throw new HttpRequestException($"MCP endpoint returned HTTP {(int)response.StatusCode}.");
        }
        if (response.Headers.TryGetValues("Mcp-Session-Id", out var values)) sessionId = values.FirstOrDefault();
        return response;
    }

    private async Task<JsonDocument> ReadDocumentAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(limits.Timeout);
        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
        using var memory = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, timeout.Token);
            if (read == 0) break;
            if (memory.Length + read > limits.MaxResponseBytes)
            {
                throw new InvalidDataException($"MCP response exceeded the {limits.MaxResponseBytes}-byte limit.");
            }
            memory.Write(buffer, 0, read);
        }

        var payload = memory.ToArray();
        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (string.Equals(mediaType, "text/event-stream", StringComparison.OrdinalIgnoreCase))
        {
            payload = ExtractSseData(payload);
        }
        return JsonDocument.Parse(payload);
    }

    private static byte[] ExtractSseData(byte[] payload)
    {
        var lines = Encoding.UTF8.GetString(payload).Split('\n');
        var data = lines.Where(line => line.StartsWith("data:", StringComparison.Ordinal))
            .Select(line => line[5..].TrimStart()).FirstOrDefault();
        return data is null
            ? throw new InvalidDataException("The MCP SSE response did not contain a data event.")
            : Encoding.UTF8.GetBytes(data);
    }

    public ValueTask DisposeAsync()
    {
        client.Dispose();
        return ValueTask.CompletedTask;
    }
}
