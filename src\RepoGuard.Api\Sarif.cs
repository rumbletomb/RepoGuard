using System.Text.Json;

namespace RepoGuard.Api;

public static class SarifExporter
{
    public static object Create(ScanRecord scan) => new
    {
        version = "2.1.0",
        schema = "https://json.schemastore.org/sarif-2.1.0.json",
        runs = new[] { new {
            tool = new { driver = new {
                name = "RepoGuard",
                informationUri = "https://github.com/repoguard/repoguard",
                rules = scan.Findings.GroupBy(f => f.RuleId).Select(g => new {
                    id = g.Key, shortDescription = new { text = g.First().Title },
                    help = new { text = g.First().Remediation }
                })
            }},
            results = scan.Findings.Select(f => new {
                ruleId = f.RuleId,
                level = f.Severity switch { Severity.Critical or Severity.High => "error", Severity.Medium => "warning", _ => "note" },
                message = new { text = f.Description },
                locations = new[] { new { physicalLocation = new {
                    artifactLocation = new { uri = f.File }, region = new { startLine = f.Line }
                }}}
            })
        }}
    };
}
