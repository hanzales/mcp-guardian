using McpGuardian.Baselines;
using McpGuardian.Authorization;
using McpGuardian.Cli;
using McpGuardian.Discovery;
using McpGuardian.Inspection;
using McpGuardian.Gateway;
using McpGuardian.Models;
using McpGuardian.Scanning;
using McpGuardian.Semantics;

if (args is ["--mcp-fixture"])
{
    return RunMcpFixture();
}

var failures = new List<string>();
Run("detects vulnerable configuration", DetectsVulnerableConfiguration);
Run("accepts secure configuration", AcceptsSecureConfiguration);
Run("rejects malformed shape", RejectsMalformedShape);
Run("accepts VS Code servers shape", AcceptsVsCodeServersShape);
Run("discovers supported client configuration", DiscoversSupportedClientConfiguration);
Run("creates stable canonical baseline", CreatesStableCanonicalBaseline);
Run("detects baseline drift", DetectsBaselineDrift);
Run("writes valid SARIF", WritesValidSarif);
Run("CLI honors fail-on threshold", CliHonorsFailOnThreshold);
Run("inspects and exports live capabilities", InspectsLiveCapabilities);
Run("detects tool schema drift", DetectsToolSchemaDrift);
Run("requires explicit stdio process opt-in", RequiresExplicitProcessOptIn);
Run("supports Streamable HTTP JSON and SSE", SupportsStreamableHttp);
Run("enforces HTTP response size limit", EnforcesHttpResponseLimit);
Run("inspects a real stdio child process", InspectsRealStdioProcess);
Run("detects semantic tool attacks", DetectsSemanticToolAttacks);
Run("detects shadowing and cross-server escalation", DetectsShadowingAndEscalation);
Run("accepts safe semantic fixture", AcceptsSafeSemanticFixture);
Run("CLI writes semantic JSON and enforces threshold", CliAnalyzesInspectionReports);
Run("accepts secure authorization evidence", AcceptsSecureAuthorizationEvidence);
Run("detects authorization vulnerabilities", DetectsAuthorizationVulnerabilities);
Run("CLI enforces authorization threshold", CliAuditsAuthorization);
Run("gateway enforces tool, path, and network policy", GatewayEnforcesPolicy);
Run("gateway requires approval without executing", GatewayRequiresApproval);
Run("gateway audit chain does not log arguments", GatewayAuditRedactsArguments);
Run("gateway proxies an allowed stdio tool call", GatewayProxiesAllowedCall);
Run("doctor reports runtime readiness", DoctorReportsRuntimeReadiness);
Run("init creates project guidance and action", InitCreatesProjectFiles);

if (failures.Count > 0)
{
    Console.Error.WriteLine($"{failures.Count} test(s) failed:");
    failures.ForEach(Console.Error.WriteLine);
    return 1;
}

Console.WriteLine("All tests passed.");
return 0;

void Run(string name, Action test)
{
    try
    {
        test();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception exception)
    {
        failures.Add($"FAIL {name}: {exception.Message}");
    }
}

void DetectsVulnerableConfiguration()
{
    var report = Scan("""
        {"mcpServers":{"bad":{"command":"npx","args":["untrusted-package","/"],"env":{"API_TOKEN":"literal-secret-value"}}}}
        """);
    Assert(report.Findings.Any(f => f.RuleId == "MCG102"), "unpinned package not detected");
    Assert(report.Findings.Any(f => f.RuleId == "MCG103"), "broad path not detected");
    Assert(report.Findings.Any(f => f.RuleId == "MCG105"), "literal secret not detected");
    Assert(report.Risk >= Severity.High, "risk should be high or critical");
}

void AcceptsSecureConfiguration()
{
    var report = Scan("""
        {"mcpServers":{"safe":{"command":"npx","args":["@example/server@1.2.3","/workspace/project"],"env":{"API_TOKEN":"${API_TOKEN}"}}}}
        """);
    Assert(report.Findings.Count == 0, "secure configuration produced findings");
}

void RejectsMalformedShape()
{
    var report = Scan("{" + "\"unrelated\":{}}");
    Assert(report.Findings.Single().RuleId == "MCG001", "missing shape not detected");
}

void AcceptsVsCodeServersShape()
{
    var report = Scan("""
        {"servers":{"safe":{"type":"stdio","command":"server","args":["--safe"]}}}
        """);
    Assert(report.Findings.Count == 0, "VS Code servers shape produced findings");
}

void DiscoversSupportedClientConfiguration()
{
    WithTempDirectory(directory =>
    {
        var cursorDirectory = Path.Combine(directory, ".cursor");
        Directory.CreateDirectory(cursorDirectory);
        File.WriteAllText(Path.Combine(cursorDirectory, "mcp.json"), "{\"mcpServers\":{}}");

        var discovered = new ConfigDiscovery().Discover(Path.Combine(directory, "home"), directory);
        Assert(discovered.Count == 1, "expected one discovered config");
        Assert(discovered[0].Client == "Cursor", "expected Cursor config");
    });
}

void CreatesStableCanonicalBaseline()
{
    WithTempDirectory(directory =>
    {
        var first = Path.Combine(directory, "first.json");
        var second = Path.Combine(directory, "second.json");
        File.WriteAllText(first, "{\"mcpServers\":{\"safe\":{\"command\":\"npx\",\"args\":[\"pkg@1.0.0\"]}}}");
        File.WriteAllText(second, "{\"mcpServers\":{\"safe\":{\"args\":[\"pkg@1.0.0\"],\"command\":\"npx\"}}}");

        var service = new ConfigBaselineService();
        var firstHash = service.Create(first).Servers["safe"];
        var secondHash = service.Create(second).Servers["safe"];
        Assert(firstHash == secondHash, "property ordering changed the fingerprint");
    });
}

void DetectsBaselineDrift()
{
    WithTempDirectory(directory =>
    {
        var config = Path.Combine(directory, "mcp.json");
        var baselinePath = Path.Combine(directory, "baseline.json");
        File.WriteAllText(config, "{\"mcpServers\":{\"safe\":{\"command\":\"server\"}}}");

        var service = new ConfigBaselineService();
        service.Save(service.Create(config), baselinePath);
        File.WriteAllText(config, "{\"mcpServers\":{\"safe\":{\"command\":\"changed\"},\"new\":{\"url\":\"https://example.com\"}}}");

        var verification = service.Verify(config, baselinePath);
        Assert(verification.Changes.Any(change => change.Server == "safe" && change.Kind == BaselineChangeKind.Modified),
            "modified server not detected");
        Assert(verification.Changes.Any(change => change.Server == "new" && change.Kind == BaselineChangeKind.Added),
            "added server not detected");
    });
}

void WritesValidSarif()
{
    var report = Scan("""
        {"mcpServers":{"bad":{"command":"bash","args":["-c","echo unsafe"]}}}
        """);
    using var writer = new StringWriter();
    ReportWriter.WriteSarif(new[] { report }, writer);
    using var document = System.Text.Json.JsonDocument.Parse(writer.ToString());
    Assert(document.RootElement.GetProperty("version").GetString() == "2.1.0", "invalid SARIF version");
    Assert(document.RootElement.GetProperty("runs")[0].GetProperty("results").GetArrayLength() > 0,
        "SARIF results are empty");
}

void CliHonorsFailOnThreshold()
{
    WithTempDirectory(directory =>
    {
        var config = Path.Combine(directory, "mcp.json");
        File.WriteAllText(config, "{\"mcpServers\":{\"bad\":{\"command\":\"bash\"}}}");
        using var output = new StringWriter();
        using var error = new StringWriter();
        var exitCode = CliApplication.Run(new[] { "scan", config, "--fail-on", "high" }, output, error);
        Assert(exitCode == 1, "CLI did not fail on a critical finding");
    });
}

void DoctorReportsRuntimeReadiness()
{
    using var output = new StringWriter();
    var code = CliApplication.Run(new[] { "doctor" }, output, new StringWriter());
    Assert(code is 0 or 1, "doctor returned an invalid exit code");
    Assert(output.ToString().Contains("MCP Guardian doctor", StringComparison.Ordinal), "doctor header was not written");
}

void InitCreatesProjectFiles()
{
    WithTempDirectory(directory =>
    {
        var original = Directory.GetCurrentDirectory();
        try
        {
            Directory.SetCurrentDirectory(directory);
            using var output = new StringWriter();
            var code = CliApplication.Run(new[] { "init", "--github-action" }, output, new StringWriter());
            Assert(code == 0, "init did not succeed");
            Assert(File.Exists(Path.Combine(directory, ".mcp-guardian", "policy.json")), "policy template was not created");
            Assert(File.Exists(Path.Combine(directory, ".github", "workflows", "mcp-guardian.yml")), "GitHub Action workflow was not created");
            var second = CliApplication.Run(new[] { "init", "--github-action" }, new StringWriter(), new StringWriter());
            Assert(second == 0, "init was not idempotent");
        }
        finally
        {
            Directory.SetCurrentDirectory(original);
        }
    });
}

void InspectsLiveCapabilities()
{
    var transport = new FakeTransport(new Dictionary<string, Queue<string>>(StringComparer.Ordinal)
    {
        ["initialize"] = Responses("""
            {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","serverInfo":{"name":"fixture","version":"1.0.0"},"capabilities":{"tools":{"listChanged":true},"resources":{},"prompts":{},"logging":{}}}}
            """),
        ["tools/list"] = Responses(
            """{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"alpha","description":"First","inputSchema":{"type":"object"}}],"nextCursor":"page-2"}}""",
            """{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"beta","inputSchema":{"type":"object","properties":{}}}]}}"""),
        ["resources/list"] = Responses("""{"jsonrpc":"2.0","id":4,"result":{"resources":[{"name":"docs","uri":"file:///docs"}]}}"""),
        ["prompts/list"] = Responses("""{"jsonrpc":"2.0","id":5,"result":{"prompts":[{"name":"review"}]}}""")
    });

    var report = new CapabilityInspector().InspectAsync("fixture.json", "fixture", transport).GetAwaiter().GetResult();
    Assert(report.Tools.Count == 2, "paginated tools were not exported");
    Assert(report.Resources.Single().Name == "docs", "resources were not exported");
    Assert(report.Prompts.Single().Name == "review", "prompts were not exported");
    Assert(report.Tools.All(tool => tool.Fingerprint.Length == 64), "tool fingerprints are invalid");
    Assert(transport.Notifications.Contains("notifications/initialized"), "initialized notification was not sent");
}

void DetectsToolSchemaDrift()
{
    WithTempDirectory(directory =>
    {
        var service = new CapabilityBaselineService();
        var baselinePath = Path.Combine(directory, "capabilities.json");
        var original = InspectionWithTools(("alpha", "a1"), ("removed", "b1"));
        service.Save(service.Create(original), baselinePath);
        var current = InspectionWithTools(("alpha", "a2"), ("added", "c1"));
        var verification = service.Verify(current, baselinePath);
        Assert(verification.Changes.Any(change => change.Tool == "alpha" && change.Kind == CapabilityChangeKind.Modified), "modified tool not detected");
        Assert(verification.Changes.Any(change => change.Tool == "removed" && change.Kind == CapabilityChangeKind.Removed), "removed tool not detected");
        Assert(verification.Changes.Any(change => change.Tool == "added" && change.Kind == CapabilityChangeKind.Added), "added tool not detected");
    });
}

void RequiresExplicitProcessOptIn()
{
    WithTempDirectory(directory =>
    {
        var config = Path.Combine(directory, "mcp.json");
        File.WriteAllText(config, "{\"mcpServers\":{\"fixture\":{\"command\":\"never-run\"}}}");
        using var output = new StringWriter();
        using var error = new StringWriter();
        var code = CliApplication.Run(new[] { "inspect", config, "--server", "fixture" }, output, error);
        Assert(code == 2, "stdio inspection did not require opt-in");
        Assert(error.ToString().Contains("--allow-process", StringComparison.Ordinal), "opt-in guidance was not shown");
    });
}

void SupportsStreamableHttp()
{
    var handler = new SequenceHttpHandler(
        HttpResponse("""{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}""", "application/json", "session-1"),
        HttpResponse("data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n", "text/event-stream"));
    var definition = new ServerDefinition("remote", null, Array.Empty<string>(), new Dictionary<string, string>(), new Uri("https://example.test/mcp"), new Dictionary<string, string>());
    var transport = new HttpMcpTransport(definition, InspectionLimits.Default, handler);
    using var first = transport.SendRequestAsync("initialize", null, default).GetAwaiter().GetResult();
    using var second = transport.SendRequestAsync("tools/list", null, default).GetAwaiter().GetResult();
    transport.DisposeAsync().GetAwaiter().GetResult();
    Assert(first.RootElement.TryGetProperty("result", out _), "JSON response was not parsed");
    Assert(second.RootElement.TryGetProperty("result", out _), "SSE response was not parsed");
    Assert(handler.Headers[1].Session == "session-1", "MCP session ID was not preserved");
    Assert(handler.Headers[1].Protocol == "2025-11-25", "MCP protocol header was not sent");
}

void EnforcesHttpResponseLimit()
{
    var handler = new SequenceHttpHandler(HttpResponse(new string('x', 128), "application/json"));
    var definition = new ServerDefinition("remote", null, Array.Empty<string>(), new Dictionary<string, string>(), new Uri("https://example.test/mcp"), new Dictionary<string, string>());
    var transport = new HttpMcpTransport(definition, new InspectionLimits(TimeSpan.FromSeconds(1), 32), handler);
    try
    {
        transport.SendRequestAsync("initialize", null, default).GetAwaiter().GetResult();
        throw new InvalidOperationException("oversized response was accepted");
    }
    catch (InvalidDataException)
    {
        // Expected.
    }
    finally
    {
        transport.DisposeAsync().GetAwaiter().GetResult();
    }
}

void InspectsRealStdioProcess()
{
    var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Process path is unavailable.");
    var assembly = Environment.GetCommandLineArgs()[0];
    var definition = new ServerDefinition(
        "stdio-fixture", executable, new[] { assembly, "--mcp-fixture" },
        new Dictionary<string, string>(), null, new Dictionary<string, string>());
    var transport = new StdioMcpTransport(definition, new InspectionLimits(TimeSpan.FromSeconds(5), 64 * 1024));
    try
    {
        var report = new CapabilityInspector().InspectAsync("fixture.json", "stdio-fixture", transport).GetAwaiter().GetResult();
        Assert(report.Transport == "stdio", "stdio transport was not reported");
        Assert(report.Tools.Single().Name == "fixture.echo", "stdio tool was not exported");
    }
    finally
    {
        transport.DisposeAsync().GetAwaiter().GetResult();
    }
}

int RunMcpFixture()
{
    string? line;
    while ((line = Console.ReadLine()) is not null)
    {
        using var document = System.Text.Json.JsonDocument.Parse(line);
        var root = document.RootElement;
        if (!root.TryGetProperty("id", out var id)) continue;
        var method = root.GetProperty("method").GetString();
        object result = method switch
        {
            "initialize" => new
            {
                protocolVersion = "2025-11-25",
                serverInfo = new { name = "stdio-fixture", version = "1.0.0" },
                capabilities = new { tools = new { } }
            },
            "tools/list" => new
            {
                tools = new[]
                {
                    new { name = "fixture.echo", description = "Echo fixture", inputSchema = new { type = "object" } }
                }
            },
            _ => new { }
        };
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { jsonrpc = "2.0", id = id.GetInt32(), result }));
        Console.Out.Flush();
    }
    return 0;
}

void DetectsSemanticToolAttacks()
{
    var report = ReadInspection("examples/security-lab/poisoned-inspection.json");
    var findings = new SemanticAnalyzer().Analyze(new[] { report }).Findings;
    Assert(findings.Any(finding => finding.RuleId == "MCG201"), "tool poisoning was not detected");
    Assert(findings.Any(finding => finding.RuleId == "MCG203"), "suspicious Unicode was not detected");
    Assert(findings.Any(finding => finding.RuleId == "MCG204"), "encoded instruction was not detected");
    Assert(findings.Any(finding => finding.RuleId == "MCG206"), "annotation inconsistency was not detected");
}

void DetectsShadowingAndEscalation()
{
    var poisoned = ReadInspection("examples/security-lab/poisoned-inspection.json");
    var shadow = ReadInspection("examples/security-lab/shadow-inspection.json");
    var findings = new SemanticAnalyzer().Analyze(new[] { poisoned, shadow }).Findings;
    Assert(findings.Any(finding => finding.RuleId == "MCG202" && finding.Severity == Severity.High), "tool shadowing was not detected");
    Assert(findings.Any(finding => finding.RuleId == "MCG205" && finding.Severity == Severity.High), "explicit cross-server escalation was not detected");
    Assert(findings.Any(finding => finding.RuleId == "MCG205" && finding.Severity == Severity.Medium), "cross-server data flow was not detected");
}

void AcceptsSafeSemanticFixture()
{
    var report = ReadInspection("examples/security-lab/safe-inspection.json");
    Assert(new SemanticAnalyzer().Analyze(new[] { report }).Findings.Count == 0, "safe fixture produced semantic findings");
}

void CliAnalyzesInspectionReports()
{
    using var output = new StringWriter();
    using var error = new StringWriter();
    var code = CliApplication.Run(new[]
    {
        "analyze", "examples/security-lab/poisoned-inspection.json", "examples/security-lab/shadow-inspection.json",
        "--format", "json", "--fail-on", "high"
    }, output, error);
    Assert(code == 1, "semantic CLI did not enforce the high threshold");
    using var document = System.Text.Json.JsonDocument.Parse(output.ToString());
    Assert(document.RootElement.GetProperty("Findings").GetArrayLength() > 0, "semantic JSON report is empty");
    Assert(!output.ToString().Contains("Ignore previous instructions", StringComparison.OrdinalIgnoreCase), "finding output copied untrusted instructions");
}

InspectionReport ReadInspection(string path) =>
    System.Text.Json.JsonSerializer.Deserialize<InspectionReport>(File.ReadAllText(path), new System.Text.Json.JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true
    }) ?? throw new InvalidDataException($"Invalid fixture: {path}");

void AcceptsSecureAuthorizationEvidence()
{
    var report = new AuthorizationAuditor().Audit(ReadAuthorization("examples/authorization-lab/secure.json"), "secure.json");
    Assert(report.Findings.Count == 0, "secure authorization evidence produced findings");
}

void DetectsAuthorizationVulnerabilities()
{
    var report = new AuthorizationAuditor().Audit(ReadAuthorization("examples/authorization-lab/vulnerable.json"), "vulnerable.json");
    foreach (var id in new[] { "MCG301", "MCG302", "MCG303", "MCG304", "MCG305", "MCG306", "MCG307", "MCG308", "MCG309", "MCG310", "MCG311", "MCG312", "MCG313", "MCG314", "MCG315" })
        Assert(report.Findings.Any(finding => finding.RuleId == id), $"authorization rule {id} did not fire");
}

void CliAuditsAuthorization()
{
    using var output = new StringWriter();
    using var error = new StringWriter();
    var code = CliApplication.Run(new[] { "audit-auth", "examples/authorization-lab/vulnerable.json", "--format", "json", "--fail-on", "high" }, output, error);
    Assert(code == 1, "authorization CLI did not enforce threshold");
    Assert(output.ToString().Contains("MCG309", StringComparison.Ordinal), "authorization JSON omitted token passthrough finding");
}

AuthorizationAuditInput ReadAuthorization(string path) =>
    System.Text.Json.JsonSerializer.Deserialize<AuthorizationAuditInput>(File.ReadAllText(path), new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })
    ?? throw new InvalidDataException($"Invalid authorization fixture: {path}");

void GatewayEnforcesPolicy()
{
    var engine = new PolicyEngine(GatewayPolicyFixture());
    var allowed = engine.Evaluate("filesystem", "read_file", System.Text.Json.JsonSerializer.SerializeToElement(new { path = "/workspace/project/README.md" }), DateTimeOffset.UtcNow);
    var pathDenied = engine.Evaluate("filesystem", "read_file", System.Text.Json.JsonSerializer.SerializeToElement(new { path = "/etc/passwd" }), DateTimeOffset.UtcNow);
    var networkDenied = engine.Evaluate("filesystem", "read_file", System.Text.Json.JsonSerializer.SerializeToElement(new { url = "https://evil.example/data" }), DateTimeOffset.UtcNow);
    Assert(allowed.Allowed, "allowlisted gateway call was denied");
    Assert(!pathDenied.Allowed && pathDenied.Reason.Contains("filesystem", StringComparison.Ordinal), "path escape was allowed");
    Assert(!networkDenied.Allowed && networkDenied.Reason.Contains("network", StringComparison.Ordinal), "network escape was allowed");
}

void GatewayRequiresApproval()
{
    var decision = new PolicyEngine(GatewayPolicyFixture()).Evaluate("filesystem", "write_file", System.Text.Json.JsonSerializer.SerializeToElement(new { path = "/workspace/project/a.txt" }), DateTimeOffset.UtcNow);
    Assert(!decision.Allowed && decision.ApprovalRequired, "approval policy did not stop execution");
}

void GatewayAuditRedactsArguments()
{
    WithTempDirectory(directory =>
    {
        var path = Path.Combine(directory, "audit.jsonl");
        using (var audit = new AuditChainWriter(path))
            audit.Write("filesystem", "read_file", new PolicyDecision(true, false, "allowed"), System.Text.Json.JsonSerializer.SerializeToElement(new { token = "literal-secret-value" }));
        using (var audit = new AuditChainWriter(path))
            audit.Write("filesystem", "read_file", new PolicyDecision(false, false, "denied"), System.Text.Json.JsonSerializer.SerializeToElement(new { path = "/tmp/example" }));
        var text = File.ReadAllText(path);
        Assert(!text.Contains("literal-secret-value", StringComparison.Ordinal), "audit event logged a secret argument");
        Assert(text.Contains("argumentHash", StringComparison.Ordinal), "audit event omitted argument hash");
        var events = File.ReadAllLines(path).Select(line => System.Text.Json.JsonDocument.Parse(line)).ToArray();
        Assert(events[1].RootElement.GetProperty("payload").GetProperty("previousHash").GetString() == events[0].RootElement.GetProperty("hash").GetString(), "audit hash chain did not continue across sessions");
        foreach (var item in events) item.Dispose();
    });
}

GatewayPolicy GatewayPolicyFixture() => new(1, "deny", new Dictionary<string, ServerPolicy>
{
    ["filesystem"] = new(new Dictionary<string, string> { ["read_file"] = "allow", ["write_file"] = "approval" }, new[] { "/workspace/project" }, new[] { "api.example.com" })
}, new GatewayLimits(60, 262144, 1048576, 10));

void GatewayProxiesAllowedCall()
{
    WithTempDirectory(directory =>
    {
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Process path is unavailable.");
        var assembly = Environment.GetCommandLineArgs()[0];
        var server = new ServerDefinition("fixture", executable, new[] { assembly, "--mcp-fixture" }, new Dictionary<string, string>(), null, new Dictionary<string, string>());
        var policy = new GatewayPolicy(1, "deny", new Dictionary<string, ServerPolicy>
        {
            ["fixture"] = new(new Dictionary<string, string> { ["fixture.echo"] = "allow" }, Array.Empty<string>(), Array.Empty<string>())
        }, new GatewayLimits(10, 65536, 65536, 5));
        var requests = string.Join('\n',
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"fixture.echo\",\"arguments\":{\"text\":\"hello\"}}}") + "\n";
        using var input = new StringReader(requests);
        using var output = new StringWriter();
        var code = new StdioGateway().RunAsync(server, policy, Path.Combine(directory, "audit.jsonl"), input, output).GetAwaiter().GetResult();
        Assert(code == 0, "gateway session failed");
        Assert(output.ToString().Contains("\"id\":2", StringComparison.Ordinal), "allowed tool response was not proxied");
    });
}

Queue<string> Responses(params string[] values) => new(values);

InspectionReport InspectionWithTools(params (string Name, string Fingerprint)[] tools) => new(
    1, "fixture.json", "fixture", "fake", DateTimeOffset.UtcNow, "2025-11-25",
    new ServerIdentity("fixture", "1.0.0"),
    new CapabilityInventory(true, false, false, false, Array.Empty<string>()),
    tools.Select(tool => new CapabilityItem(tool.Name, null, System.Text.Json.JsonSerializer.SerializeToElement(new { name = tool.Name }), tool.Fingerprint.PadRight(64, '0'))).ToArray(),
    Array.Empty<CapabilityItem>(), Array.Empty<CapabilityItem>(), Array.Empty<string>());

HttpResponseMessage HttpResponse(string content, string mediaType, string? session = null)
{
    var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
    {
        Content = new StringContent(content, System.Text.Encoding.UTF8, mediaType)
    };
    if (session is not null) response.Headers.TryAddWithoutValidation("Mcp-Session-Id", session);
    return response;
}

ScanReport Scan(string json)
{
    var path = Path.GetTempFileName();
    try
    {
        File.WriteAllText(path, json);
        return new ConfigScanner().Scan(path);
    }
    finally
    {
        File.Delete(path);
    }
}

void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

void WithTempDirectory(Action<string> action)
{
    var directory = Path.Combine(Path.GetTempPath(), $"mcp-guardian-tests-{Guid.NewGuid():N}");
    Directory.CreateDirectory(directory);
    try
    {
        action(directory);
    }
    finally
    {
        Directory.Delete(directory, true);
    }
}

sealed class FakeTransport(IReadOnlyDictionary<string, Queue<string>> responses) : IMcpTransport
{
    public string Name => "fake";
    public List<string> Notifications { get; } = [];

    public Task<System.Text.Json.JsonDocument> SendRequestAsync(string method, object? parameters, CancellationToken cancellationToken)
    {
        if (!responses.TryGetValue(method, out var queue) || queue.Count == 0) throw new InvalidOperationException($"No fake response for {method}.");
        return Task.FromResult(System.Text.Json.JsonDocument.Parse(queue.Dequeue()));
    }

    public Task SendNotificationAsync(string method, object? parameters, CancellationToken cancellationToken)
    {
        Notifications.Add(method);
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

sealed class SequenceHttpHandler(params HttpResponseMessage[] responses) : HttpMessageHandler
{
    private readonly Queue<HttpResponseMessage> queue = new(responses);
    public List<(string? Session, string? Protocol)> Headers { get; } = [];

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Headers.Add((
            request.Headers.TryGetValues("Mcp-Session-Id", out var sessions) ? sessions.Single() : null,
            request.Headers.TryGetValues("MCP-Protocol-Version", out var protocols) ? protocols.Single() : null));
        return Task.FromResult(queue.Count > 0 ? queue.Dequeue() : throw new InvalidOperationException("No HTTP fixture response."));
    }
}
