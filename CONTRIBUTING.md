# Contributing

Contributions are welcome, especially new deterministic detection rules, test fixtures, documentation, and false-positive reductions.

1. Open an issue describing substantial changes before implementation.
2. Keep rules deterministic and explain both the threat and remediation.
3. Add a vulnerable and a safe test case for each rule.
4. Target .NET 10 and avoid adding runtime dependencies without a documented security justification.
5. Run the build and dependency-free test runner before opening a pull request:

   ```bash
   dotnet build mcp-guardian.slnx --configuration Release
   dotnet run --project tests/McpGuardian.Tests/McpGuardian.Tests.csproj --configuration Release --no-build
   ```

Use private vulnerability reporting for security-sensitive findings; do not include working exploits against third-party projects in public issues.
