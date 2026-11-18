using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace InfraAdvisor.Security;

public sealed record ReviewInput(CodeRepo Repo, ScanResult Scan, string CodeName, string? ArchText, string? ArchName, string? Requester);

/// <summary>Agente revisor de seguridad: lee el código con herramientas y cierra con hallazgos estructurados.
/// El veredicto lo calcula el sistema a partir de las severidades, no el modelo.</summary>
public sealed class SecurityAgent
{
    private readonly IHttpClientFactory _http;
    private readonly DocumentService _docs;
    private readonly ILogger<SecurityAgent> _log;
    private readonly string? _apiKey;
    private readonly string _system;
    private readonly string _profileRaw;
    private readonly JsonObject _profile;
    private readonly int _maxSteps;
    private readonly int _maxTokens;
    private readonly int _maxTokensCap;
    public string Model { get; }

    public SecurityAgent(IHttpClientFactory http, DocumentService docs, IConfiguration cfg, ILogger<SecurityAgent> log)
    {
        _http = http; _docs = docs; _log = log;
        _apiKey = cfg["ANTHROPIC_API_KEY"]?.Trim().Trim('"', '\'').Trim();
        Model = cfg["SECURITY_MODEL"] ?? cfg["CLAUDE_MODEL"] ?? "claude-sonnet-5-5";
        _maxSteps = int.TryParse(cfg["SECURITY_MAX_STEPS"], out var s) ? s : 30;
        _maxTokens = int.TryParse(cfg["AGENT_MAX_TOKENS"], out var t) ? t : 16000;
        _maxTokensCap = Math.Max(_maxTokens, int.TryParse(cfg["AGENT_MAX_TOKENS_CAP"], out var c) ? c : 32000);
        var baseDir = AppContext.BaseDirectory;
        _system = File.ReadAllText(Path.Combine(baseDir, "prompts", "security-system.md"));
        _profileRaw = File.ReadAllText(cfg["SECURITY_PROFILE_PATH"] ?? Path.Combine(baseDir, "profile", "security-profile.json"));
        _profile = JsonNode.Parse(_profileRaw)!.AsObject();
    }

    public string ProfileRaw => _profileRaw;
    public string ProfileVersion => _profile["meta"]?["version"]?.GetValue<string>() ?? "";

    public delegate Task Emit(string eventName, object data);

    private static readonly Dictionary<string, string> Labels = new()
    {
        ["list_files"] = "Listando archivos",
        ["search_code"] = "Buscando en el código",
        ["read_file"] = "Leyendo",
        ["submit_review"] = "Registrando hallazgos y veredicto",
    };

    private const string ToolsJson = """
[
  {
    "name": "list_files",
    "description": "Lista rutas de archivos del repositorio, opcionalmente filtradas por prefijo de carpeta.",
    "input_schema": { "type": "object", "properties": { "prefix": { "type": "string", "description": "Ej: 'app/api/' o 'lib/'" } }, "additionalProperties": false }
  },
  {
    "name": "search_code",
    "description": "Busca una expresión regular (.NET) en el código y devuelve hasta 80 coincidencias 'ruta:línea: texto'. Excluye lockfiles.",
    "input_schema": {
      "type": "object",
      "properties": {
        "pattern": { "type": "string", "description": "Expresión regular." },
        "path_prefix": { "type": "string", "description": "Limita a rutas que empiezan así." },
        "ignore_case": { "type": "boolean" }
      },
      "required": ["pattern"],
      "additionalProperties": false
    }
  },
  {
    "name": "read_file",
    "description": "Lee un archivo con números de línea. Máximo 400 líneas por llamada; usá start_line/end_line para rangos.",
    "input_schema": {
      "type": "object",
      "properties": {
        "path": { "type": "string" },
        "start_line": { "type": "integer", "minimum": 1 },
        "end_line": { "type": "integer", "minimum": 1 }
      },
      "required": ["path"],
      "additionalProperties": false
    }
  },
  {
    "name": "submit_review",
    "description": "Cierra la revisión con los hallazgos estructurados. Llamar una sola vez, al final.",
    "input_schema": {
      "type": "object",
      "properties": {
        "summary": { "type": "string", "description": "2 a 4 líneas: estado general de seguridad de la app." },
        "findings": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "severity": { "type": "string", "enum": ["alta", "media", "baja"] },
              "rule": { "type": "string", "description": "Id de la regla del perfil, ej: SEC-02." },
              "title": { "type": "string", "description": "Una línea." },
              "description": { "type": "string", "description": "Qué pasa y por qué importa, 1-2 oraciones." },
              "evidence": { "type": "array", "items": { "type": "object", "properties": { "path": { "type": "string" }, "line": { "type": "integer" } }, "required": ["path"] } },
              "action": { "type": "string", "description": "Corrección concreta." }
            },
            "required": ["severity", "rule", "title", "description", "evidence", "action"]
          }
        },
        "discrepancies": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "topic": { "type": "string" },
              "architecture_says": { "type": "string" },
              "code_shows": { "type": "string", "description": "Con referencia ruta:línea." },
              "adjustment": { "type": "string" }
            },
            "required": ["topic", "architecture_says", "code_shows", "adjustment"]
          }
        },
        "strengths": { "type": "array", "items": { "type": "string" }, "description": "Controles bien resueltos, con referencia a archivo." },
        "not_verified": { "type": "array", "items": { "type": "string" } }
      },
      "required": ["summary", "findings", "discrepancies", "strengths", "not_verified"]
    }
  }
]
""";

    private sealed class Session
    {
        public required ReviewInput Input { get; init; }
        public HashSet<string> FilesRead { get; } = new();
        public int ToolCalls { get; set; }
        public bool EvidenceRetryUsed { get; set; }
        public JsonObject? Final { get; set; }
    }

    public async Task RunAsync(ReviewInput input, Emit emit, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_apiKey)) { await emit("error", new { message = "El servidor no tiene configurada ANTHROPIC_API_KEY." }); return; }

        var session = new Session { Input = input };
        var messages = new JsonArray { new JsonObject { ["role"] = "user", ["content"] = FirstMessage(input) } };
        var tools = JsonNode.Parse(ToolsJson)!.AsArray();
        tools[^1]!["cache_control"] = new JsonObject { ["type"] = "ephemeral" };
        long inTok = 0, outTok = 0, cacheRead = 0, cacheWrite = 0;
        var curMax = _maxTokens;
        var nudged = false;
        var client = _http.CreateClient("anthropic");
        var started = DateTime.UtcNow;

        for (var step = 0; step < _maxSteps; step++)
        {
            var msgs = (JsonArray)messages.DeepClone();
            // Caché incremental: marca el último bloque del último mensaje.
            if (msgs[^1]?["content"] is JsonArray lastContent && lastContent.Count > 0)
                lastContent[^1]!["cache_control"] = new JsonObject { ["type"] = "ephemeral" };

            var body = new JsonObject
            {
                ["model"] = Model,
                ["max_tokens"] = curMax,
                ["system"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = _system, ["cache_control"] = new JsonObject { ["type"] = "ephemeral" } }),
                ["tools"] = tools.DeepClone(),
                ["messages"] = msgs,
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, "v1/messages");
            req.Headers.Add("x-api-key", _apiKey);
            req.Headers.Add("anthropic-version", "2023-06-01");
            req.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");

            JsonNode resp;
            try
            {
                using var res = await client.SendAsync(req, ct);
                var raw = await res.Content.ReadAsStringAsync(ct);
                if (!res.IsSuccessStatusCode)
                {
                    _log.LogWarning("Claude API {Status}: {Body}", (int)res.StatusCode, raw.Length > 500 ? raw[..500] : raw);
                    await emit("error", new { message = $"La API de Claude respondió {(int)res.StatusCode}.", detail = raw.Length > 400 ? raw[..400] : raw });
                    return;
                }
                resp = JsonNode.Parse(raw)!;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogError(ex, "Error llamando a la API de Claude");
                await emit("error", new { message = "No se pudo contactar la API de Claude.", detail = ex.Message });
                return;
            }

            var usage = resp["usage"];
            inTok += L(usage, "input_tokens"); outTok += L(usage, "output_tokens");
            cacheRead += L(usage, "cache_read_input_tokens"); cacheWrite += L(usage, "cache_creation_input_tokens");

            var content = resp["content"]?.AsArray() ?? new JsonArray();
            var stop = resp["stop_reason"]?.GetValue<string>();
            if (stop == "max_tokens" && curMax < _maxTokensCap)
            {
                curMax = _maxTokensCap;
                await emit("note", new { text = "Respuesta extensa: reintentando con más margen." });
                step--;
                continue;
            }
            messages.Add(new JsonObject { ["role"] = "assistant", ["content"] = content.DeepClone() });

            var text = string.Join("\n\n", content.Where(b => T(b) == "text").Select(b => b!["text"]!.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)));
            if (!string.IsNullOrWhiteSpace(text)) await emit("note", new { text });

            var toolUses = content.Where(b => T(b) == "tool_use").ToList();
            if (toolUses.Count == 0)
            {
                if (nudged) break;
                nudged = true;
                messages.Add(new JsonObject { ["role"] = "user", ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = "Cerrá la revisión llamando a submit_review con lo que tengas." }) });
                continue;
            }

            var results = new JsonArray();
            foreach (var tu in toolUses)
            {
                var id = tu!["id"]!.GetValue<string>();
                var name = tu["name"]!.GetValue<string>();
                var tinput = tu["input"] ?? new JsonObject();
                session.ToolCalls++;
                var label = name == "read_file" ? $"Leyendo {Str(tinput, "path")}"
                          : name == "search_code" ? $"Buscando «{Trunc(Str(tinput, "pattern") ?? "", 60)}»"
                          : Labels.GetValueOrDefault(name, name);
                await emit("tool_start", new { id, name, label });

                string output; bool isError = false; string summary;
                try
                {
                    (output, isError, summary) = name switch
                    {
                        "list_files" => ListFiles(session, tinput),
                        "search_code" => SearchCode(session, tinput),
                        "read_file" => ReadFile(session, tinput),
                        "submit_review" => Submit(session, tinput),
                        _ => ($"Herramienta desconocida: {name}", true, "Herramienta desconocida"),
                    };
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "Herramienta {Tool}", name);
                    (output, isError, summary) = ($"Falla interna: {ex.Message}", true, "Falla interna");
                }
                await emit("tool_end", new { id, name, ok = !isError, summary });
                var tr = new JsonObject { ["type"] = "tool_result", ["tool_use_id"] = id, ["content"] = output };
                if (isError) tr["is_error"] = true;
                results.Add(tr);
            }
            messages.Add(new JsonObject { ["role"] = "user", ["content"] = results });
            if (session.Final is not null) break;
        }

        var usageObj = new { inputTokens = inTok, outputTokens = outTok, cacheReadTokens = cacheRead, cacheWriteTokens = cacheWrite };
        if (session.Final is null)
        {
            Log(input, session, null, usageObj, started, "sin_cierre");
            await emit("error", new { message = $"El agente no cerró la revisión dentro de {_maxSteps} pasos." });
            await emit("done", new { usage = usageObj, model = Model });
            return;
        }

        var report = BuildReport(session);
        var created = _docs.Create(new JsonObject
        {
            ["title"] = $"Revisión de seguridad — {AppName(input)}",
            ["requester"] = input.Requester ?? "",
            ["markdown"] = report.Markdown,
            ["footer"] = "Generado por el Revisor de Seguridad. Hallazgos con evidencia verificada contra el código recibido; requiere revisión de IT.",
            ["profileLabel"] = $"Seguridad v{ProfileVersion}",
        });
        await emit("verdict", report.VerdictPayload);
        if (created.Document is { } doc)
            await emit("document", new { id = doc.Id, title = doc.Title, docxUrl = $"/api/documents/{doc.Id}/docx", printUrl = $"/api/documents/{doc.Id}/print" });
        await emit("message", new { text = report.ChatSummary, html = MarkdownLite.ToHtml(MarkdownLite.Parse(report.ChatSummary)) });
        await emit("done", new { usage = usageObj, model = Model, toolCalls = session.ToolCalls, filesRead = session.FilesRead.Count });
        Log(input, session, report, usageObj, started, "ok");
    }

    // ---------- Primer mensaje ----------
    private JsonArray FirstMessage(ReviewInput i)
    {
        var scan = i.Scan.ToJson().ToJsonString(new JsonSerializerOptions { WriteIndented = false });
        return new JsonArray
        {
            Txt($"## Perfil de seguridad de IT\n```json\n{_profileRaw}\n```"),
            Txt(i.ArchText is null
                ? "## Documento de arquitectura\nNo se adjuntó. Omití las discrepancias."
                : $"## Documento de arquitectura ({i.ArchName})\n{i.ArchText}"),
            Txt($"## Chequeos automáticos sobre el código ({i.CodeName})\n```json\n{scan}\n```"),
            Txt($"## Archivos ({i.Repo.AllPaths.Count})\n{i.Repo.Tree(1500)}"),
            Txt("Revisá el código según el perfil, contrastalo con el documento de arquitectura y cerrá con submit_review."),
        };
    }

    private static JsonObject Txt(string s) => new() { ["type"] = "text", ["text"] = s };

    // ---------- Herramientas ----------
    private static string NormPath(string? p) => (p ?? "").Replace('\\', '/').TrimStart('/').Replace("./", "");

    private static (string, bool, string) ListFiles(Session s, JsonNode input)
    {
        var prefix = NormPath(Str(input, "prefix"));
        var list = s.Input.Repo.AllPaths.Where(p => prefix.Length == 0 || p.StartsWith(prefix)).ToList();
        var outp = string.Join('\n', list.Take(500)) + (list.Count > 500 ? $"\n… y {list.Count - 500} más" : "");
        return (list.Count == 0 ? "Sin archivos con ese prefijo." : outp, false, $"{list.Count} archivos");
    }

    private static (string, bool, string) SearchCode(Session s, JsonNode input)
    {
        var pattern = Str(input, "pattern") ?? "";
        var prefix = NormPath(Str(input, "path_prefix"));
        var opts = RegexOptions.CultureInvariant | (input["ignore_case"]?.GetValue<bool>() == true ? RegexOptions.IgnoreCase : RegexOptions.None);
        Regex rx;
        try { rx = new Regex(pattern, opts, TimeSpan.FromMilliseconds(100)); }
        catch (ArgumentException ex) { return ($"Expresión regular inválida: {ex.Message}", true, "Regex inválida"); }

        var hits = new List<string>();
        var total = 0;
        foreach (var (path, lines) in s.Input.Repo.Files.OrderBy(f => f.Key, StringComparer.Ordinal))
        {
            if (prefix.Length > 0 && !path.StartsWith(prefix)) continue;
            if (path.EndsWith("package-lock.json") || path.EndsWith(".lock")) continue;
            for (var i = 0; i < lines.Length; i++)
            {
                bool m;
                try { m = rx.IsMatch(lines[i]); } catch (RegexMatchTimeoutException) { continue; }
                if (!m) continue;
                total++;
                if (hits.Count < 80) hits.Add($"{path}:{i + 1}: {Trunc(lines[i].Trim(), 200)}");
            }
        }
        var outp = hits.Count == 0 ? "Sin coincidencias." : string.Join('\n', hits) + (total > hits.Count ? $"\n… {total - hits.Count} coincidencias más; afiná la búsqueda." : "");
        return (outp, false, $"{total} coincidencias");
    }

    private static (string, bool, string) ReadFile(Session s, JsonNode input)
    {
        var path = NormPath(Str(input, "path"));
        var repo = s.Input.Repo;
        if (!repo.Files.TryGetValue(path, out var lines))
        {
            if (repo.AllPaths.Contains(path)) return ("Archivo binario o demasiado grande: no se puede leer como texto.", true, "No legible");
            var name = Path.GetFileName(path);
            var similar = repo.AllPaths.Where(p => p.EndsWith("/" + name) || p == name).Take(10).ToList();
            return ($"No existe '{path}'." + (similar.Count > 0 ? " Quizás: " + string.Join(", ", similar) : ""), true, "No existe");
        }
        var start = Math.Max(1, input["start_line"]?.GetValue<int>() ?? 1);
        var end = Math.Min(lines.Length, input["end_line"]?.GetValue<int>() ?? start + 299);
        if (end - start + 1 > 400) end = start + 399;
        if (start > lines.Length) return ($"El archivo tiene {lines.Length} líneas.", true, "Fuera de rango");
        var sb = new StringBuilder($"{path} ({lines.Length} líneas), líneas {start}-{end}:\n");
        for (var i = start; i <= end; i++) sb.Append(i).Append(": ").AppendLine(Trunc(lines[i - 1], 400));
        s.FilesRead.Add(path);
        return (sb.ToString(), false, $"{path}:{start}-{end}");
    }

    private (string, bool, string) Submit(Session s, JsonNode input)
    {
        var findings = input["findings"] as JsonArray ?? new JsonArray();
        var invalid = new List<string>();
        foreach (var f in findings.OfType<JsonObject>())
        {
            var ev = f["evidence"] as JsonArray ?? new JsonArray();
            var valid = 0; var bad = 0;
            foreach (var e in ev.OfType<JsonObject>())
            {
                var path = NormPath(Str(e, "path"));
                e["path"] = path;
                var line = e["line"] is JsonValue v && v.TryGetValue<int>(out var l) ? l : (int?)null;
                var ok = line is null ? s.Input.Repo.Exists(path)
                       : s.Input.Repo.Files.TryGetValue(path, out var lines) && line >= 1 && line <= lines.Length;
                e["verified"] = ok;
                if (ok) valid++; else { bad++; invalid.Add($"{Str(f, "title")}: {path}{(line is null ? "" : ":" + line)}"); }
            }
            f["evidenceStatus"] = ev.Count == 0 ? "ausencia" : valid > 0 ? "verificada" : "invalida";
        }
        if (invalid.Count > 0 && !s.EvidenceRetryUsed)
        {
            s.EvidenceRetryUsed = true;
            return ("Evidencias que no existen en el código (ruta o línea fuera de rango). Corregilas leyendo el archivo y volvé a llamar a submit_review con todos los hallazgos:\n- " + string.Join("\n- ", invalid), true, $"{invalid.Count} evidencias inválidas: se pide corrección");
        }
        s.Final = (JsonObject)input.DeepClone();
        var counted = findings.OfType<JsonObject>().Where(f => Str(f, "evidenceStatus") != "invalida").ToList();
        var verdict = Verdict(counted);
        return ($"Revisión registrada. Veredicto calculado: {verdict}.", false, $"{counted.Count} hallazgos · {verdict.Replace('_', ' ')}");
    }

    private static string Verdict(IEnumerable<JsonObject> findings)
    {
        var sev = findings.Select(f => Str(f, "severity")).ToList();
        return sev.Contains("alta") ? "NO_APTO" : sev.Contains("media") ? "APTO_CON_OBSERVACIONES" : "APTO";
    }

    // ---------- Informe ----------
    private sealed record Report(string Markdown, string ChatSummary, object VerdictPayload, string Verdict, int Alta, int Media, int Baja, int Invalid);

    private static readonly string[] Order = { "alta", "media", "baja" };

    private Report BuildReport(Session s)
    {
        var f = s.Final!;
        var all = (f["findings"] as JsonArray ?? new JsonArray()).OfType<JsonObject>().ToList();
        var valid = all.Where(x => Str(x, "evidenceStatus") != "invalida")
                       .OrderBy(x => Array.IndexOf(Order, Str(x, "severity") ?? "baja")).ToList();
        var invalid = all.Where(x => Str(x, "evidenceStatus") == "invalida").ToList();
        var verdict = Verdict(valid);
        int a = valid.Count(x => Str(x, "severity") == "alta"), m = valid.Count(x => Str(x, "severity") == "media"), b = valid.Count(x => Str(x, "severity") == "baja");
        var verdictText = verdict switch
        {
            "NO_APTO" => "No apto para producción",
            "APTO_CON_OBSERVACIONES" => "Apto con observaciones",
            _ => "Apto",
        };
        var summary = Cell(Str(f, "summary") ?? "");
        var md = new StringBuilder();

        md.AppendLine("## Veredicto").AppendLine();
        md.AppendLine($"**{verdictText}.** {summary}").AppendLine();
        md.AppendLine($"{Pl(a, "hallazgo alto", "hallazgos altos")}, {Pl(m, "medio", "medios")} y {Pl(b, "bajo", "bajos")}. El veredicto se calcula con las reglas del perfil: una alta abierta bloquea el despliegue.").AppendLine();
        if (a > 0)
        {
            md.AppendLine("Condiciones para desplegar:").AppendLine();
            var n = 1;
            foreach (var x in valid.Where(x => Str(x, "severity") == "alta")) md.AppendLine($"{n++}. {Cell(Str(x, "title"))}");
            md.AppendLine();
        }

        md.AppendLine("## Hallazgos").AppendLine();
        if (valid.Count == 0) md.AppendLine("Sin hallazgos.").AppendLine();
        else
        {
            md.AppendLine("| # | Severidad | Regla | Hallazgo | Evidencia | Acción |");
            md.AppendLine("| --- | --- | --- | --- | --- | --- |");
            var i = 1;
            foreach (var x in valid)
            {
                var sev = Str(x, "severity") ?? "";
                var sevCell = sev == "alta" ? "**Alta**" : sev == "media" ? "Media" : "Baja";
                md.AppendLine($"| {i++} | {sevCell} | {Cell(Str(x, "rule"))} | **{Cell(Str(x, "title"))}** {Cell(Str(x, "description"))} | {Evidence(x)} | {Cell(Str(x, "action"))} |");
            }
            md.AppendLine();
            md.AppendLine("Severidades: alta bloquea el despliegue; media se corrige dentro del plan de despliegue o con excepción aprobada; baja entra al backlog.").AppendLine();
        }

        var disc = (f["discrepancies"] as JsonArray ?? new JsonArray()).OfType<JsonObject>().ToList();
        if (s.Input.ArchText is not null)
        {
            md.AppendLine("## Diferencias con el documento de arquitectura").AppendLine();
            if (disc.Count == 0) md.AppendLine("No se encontraron diferencias entre el documento y el código.").AppendLine();
            else
            {
                md.AppendLine("| Tema | Documento de arquitectura | Código | Ajuste |");
                md.AppendLine("| --- | --- | --- | --- |");
                foreach (var d in disc) md.AppendLine($"| {Cell(Str(d, "topic"))} | {Cell(Str(d, "architecture_says"))} | {Cell(Str(d, "code_shows"))} | {Cell(Str(d, "adjustment"))} |");
                md.AppendLine();
            }
        }

        var strengths = Strings(f["strengths"]);
        if (strengths.Count > 0)
        {
            md.AppendLine("## Controles verificados").AppendLine();
            foreach (var x in strengths) md.AppendLine($"- {Cell(x)}");
            md.AppendLine();
        }

        var scan = s.Input.Scan;
        var vulnsProd = scan.Vulnerabilities.Count(v => Str(v, "scope") == "produccion");
        var vulnsDev = scan.Vulnerabilities.Count - vulnsProd;
        var secretHits = scan.Signals.Count(x => x.Category == "secretos" && x.Id.StartsWith("secret-") && x.Severity == "alta");
        md.AppendLine("## Alcance y método").AppendLine();
        md.AppendLine($"Código: `{s.Input.CodeName}` ({scan.FilesTotal} archivos, {scan.FilesRead} de texto). Documento de arquitectura: {(s.Input.ArchName is null ? "no adjuntado" : $"`{s.Input.ArchName}`")}.").AppendLine();
        md.AppendLine("| Chequeo | Método | Resultado |");
        md.AppendLine("| --- | --- | --- |");
        md.AppendLine($"| Secretos en el código | Reglas tipo gitleaks | {secretHits} posibles secretos reales |");
        md.AppendLine($"| Dependencias npm | API de avisos del registro npm (la de `npm audit`) | Producción: {vulnsProd} avisos. Desarrollo: {vulnsDev} |");
        md.AppendLine($"| Dockerfile, CI, IaC, TLS, servicios externos | Reglas fijas | {scan.Signals.Count(x => x.Severity is "alta" or "media")} señales a revisar |");
        md.AppendLine($"| Revisión del código | Agente con {Model} | {s.FilesRead.Count} archivos leídos, {s.ToolCalls} llamadas a herramientas |");
        md.AppendLine();

        var nv = Strings(f["not_verified"]).Concat(scan.Notes).ToList();
        nv.Add("Historial de Git, análisis estático completo (Semgrep/CodeQL), escaneo de imagen y pruebas dinámicas: fuera del alcance de esta versión.");
        md.AppendLine("**No verificado:**").AppendLine();
        foreach (var x in nv.Distinct()) md.AppendLine($"- {Cell(x)}");
        md.AppendLine();

        if (invalid.Count > 0)
        {
            md.AppendLine("## Hallazgos descartados").AppendLine();
            md.AppendLine("El agente los reportó con evidencia que no existe en el código. No cuentan para el veredicto.").AppendLine();
            foreach (var x in invalid) md.AppendLine($"- {Cell(Str(x, "title"))} ({Evidence(x)})");
            md.AppendLine();
        }

        // Resumen para el chat
        var chat = new StringBuilder();
        chat.AppendLine($"## {verdictText}").AppendLine();
        chat.AppendLine(summary).AppendLine();
        if (valid.Count > 0)
        {
            chat.AppendLine("| Severidad | Hallazgo | Evidencia |");
            chat.AppendLine("| --- | --- | --- |");
            foreach (var x in valid.Take(12))
            {
                var sev = Str(x, "severity") ?? "";
                chat.AppendLine($"| {(sev == "alta" ? "**Alta**" : sev == "media" ? "Media" : "Baja")} | {Cell(Str(x, "title"))} | {Evidence(x)} |");
            }
            if (valid.Count > 12) chat.AppendLine().AppendLine($"Y {valid.Count - 12} hallazgos más en el documento.");
            chat.AppendLine();
        }
        if (disc.Count > 0) chat.AppendLine($"{Pl(disc.Count, "diferencia", "diferencias")} con el documento de arquitectura.");
        if (invalid.Count > 0) chat.AppendLine($"{Pl(invalid.Count, "hallazgo descartado", "hallazgos descartados")} por evidencia inexistente.");
        chat.AppendLine("El detalle completo está en el documento.");

        var payload = new
        {
            verdict, verdictText, alta = a, media = m, baja = b, discrepancies = disc.Count, discarded = invalid.Count,
            findings = valid.Select(x => new { severity = Str(x, "severity"), rule = Str(x, "rule"), title = Str(x, "title"), evidence = EvidencePlain(x) }).ToList(),
        };
        return new Report(md.ToString(), chat.ToString(), payload, verdict, a, m, b, invalid.Count);
    }

    private static string Evidence(JsonObject f)
    {
        var ev = (f["evidence"] as JsonArray ?? new JsonArray()).OfType<JsonObject>().ToList();
        if (ev.Count == 0) return "—";
        return string.Join(", ", ev.Take(4).Select(e =>
        {
            var ok = e["verified"]?.GetValue<bool>() == true;
            var line = e["line"] is JsonValue v && v.TryGetValue<int>(out var l) ? $":{l}" : "";
            return $"`{Cell(Str(e, "path"))}{line}`" + (ok ? "" : " (no existe)");
        })) + (ev.Count > 4 ? $" y {ev.Count - 4} más" : "");
    }

    private static string EvidencePlain(JsonObject f) =>
        string.Join(", ", (f["evidence"] as JsonArray ?? new JsonArray()).OfType<JsonObject>().Take(4)
            .Select(e => Str(e, "path") + (e["line"] is JsonValue v && v.TryGetValue<int>(out var l) ? $":{l}" : "")));

    private static List<string> Strings(JsonNode? n) => (n as JsonArray ?? new JsonArray()).Select(x => x?.GetValue<string>() ?? "").Where(x => x.Length > 0).ToList();

    private static string Cell(string? s) => (s ?? "").Replace("\r", " ").Replace("\n", " ").Replace("|", "/").Trim();

    private static string AppName(ReviewInput i)
    {
        try
        {
            if (i.Repo.Files.TryGetValue("package.json", out var lines) && JsonNode.Parse(string.Join('\n', lines))?["name"]?.GetValue<string>() is { Length: > 0 } n) return n;
        }
        catch { }
        return Path.GetFileNameWithoutExtension(i.CodeName);
    }

    // ---------- Registro de uso ----------
    private void Log(ReviewInput i, Session s, Report? r, object usage, DateTime started, string result)
    {
        var entry = new
        {
            tipo = "seguridad", resultado = result, app = AppName(i), archivos = i.Scan.FilesTotal, archivosLeidos = s.FilesRead.Count,
            herramientas = s.ToolCalls, veredicto = r?.Verdict, altas = r?.Alta, medias = r?.Media, bajas = r?.Baja, descartados = r?.Invalid,
            documento = i.ArchName is not null, segundos = (int)(DateTime.UtcNow - started).TotalSeconds, tokens = usage, modelo = Model,
        };
        _log.LogInformation("USO {Uso}", JsonSerializer.Serialize(entry));
    }

    private static string? T(JsonNode? b) => b?["type"]?.GetValue<string>();
    private static long L(JsonNode? n, string k) => n?[k] is JsonValue v && v.TryGetValue<long>(out var l) ? l : 0;
    private static string? Str(JsonNode? n, string k) => n?[k] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
    private static string Pl(int n, string uno, string varios) => $"{n} {(n == 1 ? uno : varios)}";
    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}
