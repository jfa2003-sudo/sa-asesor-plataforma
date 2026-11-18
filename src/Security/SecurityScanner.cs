using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace InfraAdvisor.Security;

/// <summary>Señal de un chequeo determinístico, con evidencia (archivo:línea) cuando existe.</summary>
public sealed record Signal(string Id, string Category, string Severity, string Title, string? Path = null, int? Line = null, string? Detail = null);

public sealed class ScanResult
{
    public List<Signal> Signals { get; } = new();
    public List<string> Stack { get; } = new();
    public List<string> EnvSecretNames { get; } = new();
    public Dictionary<string, (int Count, string Path, int Line)> ExternalHosts { get; } = new();
    public List<JsonObject> Vulnerabilities { get; } = new();
    public List<string> Notes { get; } = new();
    public int FilesRead { get; set; }
    public int FilesTotal { get; set; }

    public JsonObject ToJson() => new()
    {
        ["filesTotal"] = FilesTotal,
        ["filesRead"] = FilesRead,
        ["stack"] = new JsonArray(Stack.Select(s => (JsonNode)s).ToArray()),
        ["signals"] = new JsonArray(Signals.Select(s => (JsonNode)new JsonObject
        {
            ["id"] = s.Id, ["category"] = s.Category, ["severity"] = s.Severity, ["title"] = s.Title,
            ["path"] = s.Path, ["line"] = s.Line, ["detail"] = s.Detail,
        }).ToArray()),
        ["envSecretNames"] = new JsonArray(EnvSecretNames.Select(s => (JsonNode)s).ToArray()),
        ["externalHosts"] = new JsonArray(ExternalHosts.OrderByDescending(h => h.Value.Count).Take(25).Select(h => (JsonNode)new JsonObject
        {
            ["host"] = h.Key, ["refs"] = h.Value.Count, ["example"] = $"{h.Value.Path}:{h.Value.Line}",
        }).ToArray()),
        ["vulnerabilities"] = new JsonArray(Vulnerabilities.Select(v => v.DeepClone()).ToArray()),
        ["notes"] = new JsonArray(Notes.Select(s => (JsonNode)s).ToArray()),
    };
}

/// <summary>Chequeos determinísticos sobre el código. No ejecuta nada del repo.</summary>
public sealed class SecurityScanner
{
    private readonly IHttpClientFactory _http;
    private readonly ILogger<SecurityScanner> _log;
    private readonly string _npmAuditUrl;

    public SecurityScanner(IHttpClientFactory http, ILogger<SecurityScanner> log, IConfiguration cfg)
    {
        _http = http; _log = log;
        _npmAuditUrl = cfg["NPM_AUDIT_URL"] ?? "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";
    }

    private static readonly RegexOptions O = RegexOptions.Compiled | RegexOptions.CultureInvariant;

    private static readonly (string Id, string Title, Regex Rx)[] SecretRules =
    {
        ("aws-key", "Clave de acceso de AWS", new Regex(@"\bAKIA[0-9A-Z]{16}\b", O)),
        ("google-api-key", "API key de Google", new Regex(@"\bAIza[0-9A-Za-z_\-]{35}\b", O)),
        ("private-key", "Clave privada en texto", new Regex(@"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", O)),
        ("github-token", "Token de GitHub", new Regex(@"\bgh[pousr]_[A-Za-z0-9]{36,}\b", O)),
        ("slack-token", "Token de Slack", new Regex(@"\bxox[baprs]-[0-9A-Za-z-]{10,}", O)),
        ("anthropic-key", "API key de Anthropic", new Regex(@"\bsk-ant-[A-Za-z0-9_\-]{20,}", O)),
        ("openai-key", "API key de OpenAI", new Regex(@"\bsk-(proj-)?[A-Za-z0-9]{32,}\b", O)),
        ("stripe-key", "Clave de Stripe", new Regex(@"\b(sk|rk)_live_[0-9a-zA-Z]{20,}", O)),
        ("azure-storage-key", "Clave de cuenta de Azure Storage", new Regex(@"AccountKey=[A-Za-z0-9+/=]{40,}", O)),
        ("jwt", "Token JWT", new Regex(@"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", O)),
        ("conn-password", "Contraseña en cadena de conexión", new Regex(@"(?i)\b(password|pwd)\s*=\s*[^;""'\s<>{}$]{6,}\s*;", O)),
        ("generic-secret", "Valor secreto asignado en el código", new Regex(@"(?i)\b[\w-]*(secret|password|passwd|api_?key|apikey|access_?token|private_?key)[\w-]*[""']?\s*[:=]\s*[""'][^""'\s]{12,}[""']", O)),
    };

    private static readonly (string Id, string Title, Regex Rx)[] TlsRules =
    {
        ("tls-reject-false", "Validación de certificado TLS desactivada", new Regex(@"rejectUnauthorized\s*:\s*false", O)),
        ("tls-node-env", "NODE_TLS_REJECT_UNAUTHORIZED desactiva la validación TLS", new Regex(@"NODE_TLS_REJECT_UNAUTHORIZED", O)),
        ("tls-verify-false", "verify=False en llamadas HTTP", new Regex(@"verify\s*=\s*False", O)),
        ("tls-sslmode-disable", "sslmode=disable en la conexión a base", new Regex(@"(?i)sslmode\s*=\s*disable", O)),
        ("tls-trust-server-cert", "TrustServerCertificate=true", new Regex(@"(?i)TrustServerCertificate\s*=\s*(true|yes)", O)),
        ("tls-encrypt-false", "Encrypt=False en la conexión a base", new Regex(@"(?i)\bEncrypt\s*=\s*(false|no)\b", O)),
        ("tls-callback", "Callback que acepta cualquier certificado", new Regex(@"DangerousAcceptAnyServerCertificateValidator|ServerCertificateCustomValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true", O)),
        ("tls-ssl-off", "Comentario o configuración con SSL apagado", new Regex(@"(?i)\bssl\s*=\s*off\b", O)),
        ("tls-env-false", "Variable de TLS/SSL en false", new Regex(@"^\s*[A-Z0-9_]*(SSL|TLS)[A-Z0-9_]*\s*=\s*(false|0|off)\s*$", O)),
    };

    private static readonly Regex SecretEnvName = new(@"(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|APP_?KEY|PRIVATE|_KEY$|^KEY$|CERT|BASIC|CONNECTION_?STRING|CREDENTIAL)", O);
    private static readonly Regex EnvLine = new(@"^\s*#?\s*([A-Z][A-Z0-9_]{2,})\s*=", O);
    private static readonly Regex UrlRx = new(@"https?://([a-z0-9][a-z0-9.-]+\.[a-z]{2,})", O | RegexOptions.IgnoreCase);
    private static readonly Regex Placeholder = new(@"(?i)(changeme|example|placeholder|your[-_]|xxx|<|\$\{|process\.env|test|dummy|fake|sample)", O);

    private static bool IsTest(string p) => Regex.IsMatch(p, @"(^|/)(tests?|__tests__|spec|fixtures|mocks?)/|\.(test|spec)\.[a-z]+$", RegexOptions.IgnoreCase);
    private static bool IsDoc(string p) => p.EndsWith(".md", StringComparison.OrdinalIgnoreCase);
    private static bool IsLock(string p) => p.EndsWith("package-lock.json") || p.EndsWith(".lock") || p.EndsWith("yarn.lock") || p.EndsWith("pnpm-lock.yaml");
    private static bool IsEnvExample(string p) => Regex.IsMatch(Path.GetFileName(p), @"^\.env\.(example|sample|template|dist)$|\.env\.example$", RegexOptions.IgnoreCase);

    public async Task<ScanResult> ScanAsync(CodeRepo repo, CancellationToken ct)
    {
        var r = new ScanResult { FilesTotal = repo.AllPaths.Count, FilesRead = repo.Files.Count };
        DetectStack(repo, r);
        ScanSecretFiles(repo, r);
        ScanSecrets(repo, r);
        ScanEnv(repo, r);
        ScanTls(repo, r);
        ScanCertsOnDisk(repo, r);
        ScanLocalState(repo, r);
        ScanDocker(repo, r);
        ScanCi(repo, r);
        ScanIac(repo, r);
        ScanHosts(repo, r);
        await ScanNpmAsync(repo, r, ct);
        return r;
    }

    private static void DetectStack(CodeRepo repo, ScanResult r)
    {
        foreach (var pj in repo.Files.Keys.Where(p => Path.GetFileName(p) == "package.json"))
        {
            try
            {
                var j = JsonNode.Parse(string.Join('\n', repo.Files[pj]));
                var deps = (j?["dependencies"] as JsonObject)?.Select(d => $"{d.Key}@{d.Value}").ToList() ?? new();
                r.Stack.Add($"Node.js ({pj}) engines={j?["engines"]?.ToJsonString() ?? "-"} deps: {string.Join(", ", deps.Take(30))}");
            }
            catch { r.Stack.Add($"Node.js ({pj}), package.json ilegible"); }
        }
        foreach (var cs in repo.Files.Keys.Where(p => p.EndsWith(".csproj")))
        {
            var tf = repo.Files[cs].Select(l => Regex.Match(l, @"<TargetFrameworks?>([^<]+)<")).FirstOrDefault(m => m.Success)?.Groups[1].Value;
            r.Stack.Add($".NET ({cs}) {tf}");
        }
        foreach (var py in repo.AllPaths.Where(p => Path.GetFileName(p) is "requirements.txt" or "pyproject.toml" or "Pipfile")) r.Stack.Add($"Python ({py})");
        foreach (var jv in repo.AllPaths.Where(p => Path.GetFileName(p) is "pom.xml" or "build.gradle")) r.Stack.Add($"Java ({jv})");
        foreach (var go in repo.AllPaths.Where(p => Path.GetFileName(p) == "go.mod")) r.Stack.Add($"Go ({go})");
    }

    private static void ScanSecretFiles(CodeRepo repo, ScanResult r)
    {
        foreach (var p in repo.AllPaths)
        {
            var name = Path.GetFileName(p);
            if (name.StartsWith(".env", StringComparison.OrdinalIgnoreCase) && !IsEnvExample(p))
                r.Signals.Add(new("secret-env-file", "secretos", "alta", "Archivo .env incluido en el código", p));
            if (Regex.IsMatch(name, @"\.(pem|key|pfx|p12|jks)$", RegexOptions.IgnoreCase) && !IsTest(p))
                r.Signals.Add(new("secret-key-file", "secretos", "alta", "Archivo de certificado o clave incluido en el código", p));
        }
    }

    private static void ScanSecrets(CodeRepo repo, ScanResult r)
    {
        var count = 0;
        foreach (var (p, lines) in repo.Files)
        {
            if (IsLock(p) || IsEnvExample(p)) continue;
            for (var i = 0; i < lines.Length && count < 200; i++)
            {
                var line = lines[i];
                if (line.Length > 2000) continue;
                foreach (var (id, title, rx) in SecretRules)
                {
                    var m = rx.Match(line);
                    if (!m.Success) continue;
                    if (id == "generic-secret" && Placeholder.IsMatch(m.Value)) continue;
                    var test = IsTest(p) || IsDoc(p);
                    r.Signals.Add(new($"secret-{id}", "secretos", test ? "baja" : "alta",
                        title + (test ? " (en archivo de prueba o documentación: revisar si es real)" : ""), p, i + 1, Mask(m.Value)));
                    count++;
                    break;
                }
            }
        }
    }

    private static string Mask(string v) => v.Length <= 10 ? "***" : v[..6] + "…" + new string('*', 4);

    private static void ScanEnv(CodeRepo repo, ScanResult r)
    {
        var names = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var (p, lines) in repo.Files.Where(f => IsEnvExample(f.Key)))
            foreach (var l in lines)
            {
                var m = EnvLine.Match(l);
                if (m.Success && SecretEnvName.IsMatch(m.Groups[1].Value)) names.Add(m.Groups[1].Value);
            }
        var envRef = new Regex(@"(?:process\.env\.|Environment\.GetEnvironmentVariable\(""|os\.environ(?:\.get)?\(?\[?[""']|os\.getenv\([""'])([A-Z][A-Z0-9_]{2,})", O);
        foreach (var (p, line, text) in repo.Grep(envRef, p => !IsTest(p) && !IsLock(p)))
            foreach (Match m in envRef.Matches(text))
                if (SecretEnvName.IsMatch(m.Groups[1].Value)) names.Add(m.Groups[1].Value);
        r.EnvSecretNames.AddRange(names);
        if (names.Count > 0)
            r.Signals.Add(new("secrets-in-env", "secretos", "info", $"La app lee {names.Count} secretos de variables de entorno: verificar que en producción vengan de Key Vault", null, null, string.Join(", ", names)));

        foreach (var (p, line, text) in repo.Grep(new Regex(@"^\s*env_file\s*:", O), p => Regex.IsMatch(p, @"(docker-)?compose[^/]*\.ya?ml$")))
            r.Signals.Add(new("secrets-env-file-compose", "secretos", "info", "docker-compose carga variables desde un archivo de entorno", p, line, text.Trim()));
    }

    private static void ScanTls(CodeRepo repo, ScanResult r)
    {
        foreach (var (p, lines) in repo.Files)
        {
            if (IsLock(p) || IsDoc(p)) continue;
            for (var i = 0; i < lines.Length; i++)
                foreach (var (id, title, rx) in TlsRules)
                {
                    if (id == "tls-env-false" && !Path.GetFileName(p).StartsWith(".env")) continue;
                    if (!rx.IsMatch(lines[i])) continue;
                    r.Signals.Add(new(id, "tls", IsTest(p) ? "baja" : "media", title, p, i + 1, lines[i].Trim()[..Math.Min(160, lines[i].Trim().Length)]));
                    break;
                }
        }
    }

    private static void ScanCertsOnDisk(CodeRepo repo, ScanResult r)
    {
        var rx = new Regex(@"(readFileSync|readFile|File\.ReadAll\w+|X509Certificate2\(|open\()[^\n]{0,120}\.(pem|key|crt|pfx|p12)|[""'][^""'\s]+\.(pem|key|pfx|p12)[""']", O | RegexOptions.IgnoreCase);
        foreach (var (p, line, text) in repo.Grep(rx, p => !IsTest(p) && !IsDoc(p) && !IsLock(p) && !p.EndsWith(".gitignore") && !p.EndsWith(".dockerignore")).Take(15))
            r.Signals.Add(new("cert-on-disk", "secretos", "media", "Certificado o clave leído desde archivo en disco", p, line, text.Trim()[..Math.Min(160, text.Trim().Length)]));
    }

    private static void ScanLocalState(CodeRepo repo, ScanResult r)
    {
        var rx = new Regex(@"node:sqlite|better-sqlite3|['""]sqlite3['""]|Microsoft\.Data\.Sqlite|import sqlite3|DatabaseSync\(", O);
        foreach (var (p, line, text) in repo.Grep(rx, p => !IsTest(p) && !IsDoc(p) && !IsLock(p) && !p.EndsWith(".d.ts")).Take(5))
            r.Signals.Add(new("state-sqlite", "persistencia", "media", "Datos en SQLite local (archivo en disco)", p, line, text.Trim()[..Math.Min(120, text.Trim().Length)]));
    }

    private static void ScanDocker(CodeRepo repo, ScanResult r)
    {
        var dockerfiles = repo.Files.Keys.Where(p => Regex.IsMatch(Path.GetFileName(p), @"^(Dockerfile|Containerfile)(\..+)?$")).ToList();
        if (dockerfiles.Count == 0) { r.Notes.Add("No hay Dockerfile."); return; }
        var ignore = repo.Files.Keys.FirstOrDefault(p => Path.GetFileName(p) == ".dockerignore");
        foreach (var df in dockerfiles)
        {
            var lines = repo.Files[df];
            string? lastUser = null; int userLine = 0;
            for (var i = 0; i < lines.Length; i++)
            {
                var l = lines[i].Trim();
                var from = Regex.Match(l, @"^FROM\s+(\S+)", RegexOptions.IgnoreCase);
                if (from.Success)
                {
                    var img = from.Groups[1].Value;
                    if (!img.Contains('@') && img != "scratch")
                        r.Signals.Add(new("docker-unpinned", "imagen", (img.EndsWith(":latest") || !img.Contains(':')) ? "media" : "baja",
                            "Imagen base sin fijar por digest" + (img.EndsWith(":latest") || !img.Contains(':') ? " (latest o sin versión)" : ""), df, i + 1, img));
                }
                var user = Regex.Match(l, @"^USER\s+(\S+)", RegexOptions.IgnoreCase);
                if (user.Success) { lastUser = user.Groups[1].Value; userLine = i + 1; }
                var envSecret = Regex.Match(l, @"^(ENV|ARG)\s+([A-Z0-9_]+)[= ]+(\S+)", RegexOptions.IgnoreCase);
                if (envSecret.Success && SecretEnvName.IsMatch(envSecret.Groups[2].Value) && envSecret.Groups[3].Value.Length > 3)
                    r.Signals.Add(new("docker-secret", "secretos", "alta", "Secreto definido en el Dockerfile", df, i + 1, envSecret.Groups[2].Value));
                if (Regex.IsMatch(l, @"^ADD\s+https?://", RegexOptions.IgnoreCase))
                    r.Signals.Add(new("docker-add-url", "imagen", "baja", "ADD desde URL remota sin verificación", df, i + 1, l));
            }
            if (lastUser is null || lastUser is "root" or "0")
                r.Signals.Add(new("docker-root", "imagen", "media", "El contenedor corre como root", df, lastUser is null ? null : userLine));
            else
                r.Signals.Add(new("docker-nonroot", "imagen", "ok", $"El contenedor corre con usuario sin privilegios ({lastUser})", df, userLine));
        }
        if (ignore is null)
            r.Signals.Add(new("docker-no-ignore", "imagen", "media", "Sin .dockerignore: .env, datos o .git pueden terminar en la imagen", dockerfiles[0]));
        else if (!repo.Files[ignore].Any(l => l.Trim().StartsWith(".env")))
            r.Signals.Add(new("docker-ignore-env", "imagen", "media", ".dockerignore no excluye archivos .env", ignore));
    }

    private static void ScanCi(CodeRepo repo, ScanResult r)
    {
        var wfs = repo.Files.Keys.Where(p => p.StartsWith(".github/workflows/") || p.EndsWith(".gitlab-ci.yml") || p.EndsWith("azure-pipelines.yml")).ToList();
        if (wfs.Count == 0)
        {
            r.Signals.Add(new("ci-none", "entrega", "media", "No hay pipeline de CI"));
        }
        var all = string.Join('\n', wfs.SelectMany(w => repo.Files[w])).ToLowerInvariant();
        var tools = new (string Id, string Name, string Rx)[]
        {
            ("sast", "Análisis estático (CodeQL/Semgrep/SonarQube)", "codeql|semgrep|sonar"),
            ("secrets", "Escaneo de secretos (gitleaks/trufflehog)", "gitleaks|trufflehog|secret-scan"),
            ("image", "Escaneo de imagen (Trivy/Grype)", "trivy|grype|anchore"),
            ("deps", "Auditoría de dependencias", @"npm audit|pnpm audit|yarn audit|dotnet list package --vulnerable|pip-audit|snyk|osv-scanner|dependency-check"),
            ("deploy", "Despliegue automatizado", @"azure/webapps-deploy|azure/container-apps-deploy|az (webapp|containerapp|deployment)|docker push|azd deploy|kubectl apply|terraform apply"),
        };
        foreach (var (id, name, rx) in tools)
        {
            var present = wfs.Count > 0 && Regex.IsMatch(all, rx);
            r.Signals.Add(new($"ci-{id}", "entrega", present ? "ok" : (id is "deploy" ? "info" : "media"), (present ? "Presente en CI: " : "Falta en CI: ") + name, wfs.FirstOrDefault()));
        }
        r.Signals.Add(new("ci-dependabot", "entrega", repo.AllPaths.Any(p => p.EndsWith(".github/dependabot.yml") || p.EndsWith(".github/dependabot.yaml")) ? "ok" : "baja",
            repo.AllPaths.Any(p => p.Contains("dependabot.y")) ? "Dependabot configurado" : "Sin Dependabot"));
        foreach (var w in wfs)
        {
            var lines = repo.Files[w];
            for (var i = 0; i < lines.Length; i++)
            {
                var m = Regex.Match(lines[i], @"uses:\s*([\w.-]+/[\w./-]+)@([\w.-]+)");
                if (m.Success && !Regex.IsMatch(m.Groups[2].Value, "^[0-9a-f]{40}$"))
                { r.Signals.Add(new("ci-unpinned-action", "entrega", "baja", "GitHub Actions fijadas por tag y no por SHA", w, i + 1, m.Value)); break; }
            }
            if (!lines.Any(l => Regex.IsMatch(l, @"^\s*permissions\s*:")))
                r.Signals.Add(new("ci-no-permissions", "entrega", "baja", "Workflow sin bloque permissions (token con permisos por defecto)", w));
        }
    }

    private static void ScanIac(CodeRepo repo, ScanResult r)
    {
        var iac = repo.AllPaths.Where(p => Regex.IsMatch(p, @"\.(bicep|tf)$|azuredeploy\.json$|(^|/)azure\.yaml$|(^|/)main\.parameters\.json$", RegexOptions.IgnoreCase)).ToList();
        r.Signals.Add(iac.Count > 0
            ? new("iac-present", "entrega", "ok", $"Infraestructura como código presente ({iac.Count} archivos)", iac[0])
            : new("iac-missing", "entrega", "alta", "No hay infraestructura como código (Bicep, Terraform, ARM)"));
    }

    private static void ScanHosts(CodeRepo repo, ScanResult r)
    {
        var skip = new Regex(@"(^|\.)(localhost|example\.(com|org)|w3\.org|schema\.org|npmjs\.(org|com)|github\.com|githubusercontent\.com|nextjs\.org|reactjs\.org|react\.dev|mozilla\.org|microsoft\.com|vercel\.com|json-schema\.org|opensource\.org|tc39\.es|developer\.\S+|apache\.org|ietf\.org|creativecommons\.org)$", O);
        foreach (var (p, lines) in repo.Files)
        {
            if (IsLock(p) || IsDoc(p) || IsTest(p) || p.EndsWith(".svg") || p.EndsWith(".json") && p.Contains("public/")) continue;
            for (var i = 0; i < lines.Length; i++)
                foreach (Match m in UrlRx.Matches(lines[i]))
                {
                    var host = m.Groups[1].Value.ToLowerInvariant().TrimEnd('.');
                    if (skip.IsMatch(host) || Regex.IsMatch(host, @"^\d+\.\d+\.\d+\.\d+$")) continue;
                    r.ExternalHosts[host] = r.ExternalHosts.TryGetValue(host, out var v) ? (v.Count + 1, v.Path, v.Line) : (1, p, i + 1);
                }
        }
    }

    // ---------- Dependencias npm: lockfile + API de avisos del registro (la misma que usa npm audit) ----------
    private async Task ScanNpmAsync(CodeRepo repo, ScanResult r, CancellationToken ct)
    {
        foreach (var other in repo.AllPaths.Where(p => Path.GetFileName(p) is "requirements.txt" or "pyproject.toml" or "pom.xml" or "build.gradle" or "go.mod" || p.EndsWith(".csproj")))
            r.Notes.Add($"Dependencias de {other} no evaluadas en esta versión (solo npm).");

        var locks = repo.Files.Keys.Where(p => Path.GetFileName(p) == "package-lock.json").ToList();
        if (locks.Count == 0)
        {
            if (repo.AllPaths.Any(p => Path.GetFileName(p) == "package.json"))
                r.Signals.Add(new("deps-no-lock", "dependencias", "media", "Proyecto npm sin package-lock.json: versiones no reproducibles ni auditables"));
            return;
        }
        foreach (var lockPath in locks)
        {
            Dictionary<string, Dictionary<string, bool>> pkgs; // nombre -> versión -> ¿producción?
            try { pkgs = ParseLock(string.Join('\n', repo.Files[lockPath])); }
            catch (Exception ex) { r.Notes.Add($"No se pudo leer {lockPath}: {ex.Message}"); continue; }

            // Dos consultas: solo versiones de producción, y todas. Lo que aparece solo en la segunda es de desarrollo.
            JsonObject Body(bool prodOnly)
            {
                var b = new JsonObject();
                foreach (var (name, vers) in pkgs)
                {
                    var vs = vers.Where(v => !prodOnly || v.Value).Select(v => (JsonNode)v.Key).ToArray();
                    if (vs.Length > 0) b[name] = new JsonArray(vs);
                }
                return b;
            }
            var prodResp = await AuditAsync(Body(true), r, ct);
            var allResp = await AuditAsync(Body(false), r, ct);
            if (prodResp is null || allResp is null) continue;

            var prodIds = new HashSet<string>();
            foreach (var (name, advs) in prodResp)
                foreach (var a in advs?.AsArray() ?? new JsonArray())
                    prodIds.Add($"{name}|{a?["id"]}");

            int prodHigh = 0, prodMod = 0, devHigh = 0, devOther = 0;
            foreach (var (name, advs) in allResp)
            {
                foreach (var a in advs?.AsArray() ?? new JsonArray())
                {
                    var prod = prodIds.Contains($"{name}|{a?["id"]}");
                    var sev = a?["severity"]?.GetValue<string>() ?? "unknown";
                    r.Vulnerabilities.Add(new JsonObject
                    {
                        ["package"] = name,
                        ["versions"] = string.Join(", ", pkgs[name].Where(v => !prod || v.Value).Select(v => v.Key)),
                        ["severity"] = sev,
                        ["scope"] = prod ? "produccion" : "desarrollo",
                        ["title"] = a?["title"]?.GetValue<string>(),
                        ["url"] = a?["url"]?.GetValue<string>(),
                        ["vulnerable"] = a?["vulnerable_versions"]?.GetValue<string>(),
                        ["lockfile"] = lockPath,
                    });
                    var high = sev is "high" or "critical";
                    if (prod && high) prodHigh++; else if (prod) prodMod++; else if (high) devHigh++; else devOther++;
                }
            }
            if (prodHigh > 0) r.Signals.Add(new("deps-prod-high", "dependencias", "alta", $"{prodHigh} vulnerabilidades altas o críticas en dependencias de producción", lockPath));
            if (prodMod > 0) r.Signals.Add(new("deps-prod-moderate", "dependencias", "baja", $"{prodMod} vulnerabilidades moderadas o bajas en dependencias de producción", lockPath));
            if (devHigh + devOther > 0) r.Signals.Add(new("deps-dev", "dependencias", "baja", $"{devHigh} altas/críticas y {devOther} menores en dependencias de desarrollo (no llegan a producción si el build las excluye)", lockPath));
            if (prodHigh + prodMod + devHigh + devOther == 0) r.Signals.Add(new("deps-clean", "dependencias", "ok", "Sin vulnerabilidades conocidas en dependencias npm", lockPath));
        }
    }

    private async Task<JsonObject?> AuditAsync(JsonObject body, ScanResult r, CancellationToken ct)
    {
        if (body.Count == 0) return new JsonObject();
        try
        {
            var client = _http.CreateClient("npm");
            using var res = await client.PostAsJsonAsync(_npmAuditUrl, body, ct);
            if (!res.IsSuccessStatusCode) { r.Notes.Add($"API de avisos de npm respondió {(int)res.StatusCode}; dependencias no evaluadas."); return null; }
            return (await JsonNode.ParseAsync(await res.Content.ReadAsStreamAsync(ct), cancellationToken: ct)) as JsonObject;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "npm audit");
            r.Notes.Add("No se pudo consultar la API de avisos de npm; dependencias no evaluadas.");
            return null;
        }
    }

    private static Dictionary<string, Dictionary<string, bool>> ParseLock(string json)
    {
        var root = JsonNode.Parse(json)!.AsObject();
        var map = new Dictionary<string, Dictionary<string, bool>>(StringComparer.Ordinal);
        void Add(string name, string? ver, bool dev)
        {
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(ver) || ver.Contains(':')) return; // file:, git:, link:
            if (!map.TryGetValue(name, out var e)) map[name] = e = new Dictionary<string, bool>(StringComparer.Ordinal);
            e[ver] = (e.TryGetValue(ver, out var p) && p) || !dev;
        }
        if (root["packages"] is JsonObject packages) // lockfile v2/v3
        {
            foreach (var (key, val) in packages)
            {
                if (string.IsNullOrEmpty(key) || val is not JsonObject o) continue;
                var idx = key.LastIndexOf("node_modules/", StringComparison.Ordinal);
                if (idx < 0) continue;
                var name = o["name"]?.GetValue<string>() ?? key[(idx + "node_modules/".Length)..];
                var dev = o["dev"]?.GetValue<bool>() == true || o["devOptional"]?.GetValue<bool>() == true;
                Add(name, o["version"]?.GetValue<string>(), dev);
            }
        }
        else if (root["dependencies"] is JsonObject deps) // lockfile v1
        {
            void Walk(JsonObject d)
            {
                foreach (var (name, val) in d)
                {
                    if (val is not JsonObject o) continue;
                    Add(name, o["version"]?.GetValue<string>(), o["dev"]?.GetValue<bool>() == true);
                    if (o["dependencies"] is JsonObject sub) Walk(sub);
                }
            }
            Walk(deps);
        }
        return map;
    }
}
