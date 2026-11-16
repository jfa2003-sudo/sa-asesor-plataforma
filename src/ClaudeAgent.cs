using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace InfraAdvisor;

public sealed record ChatMessage(string Role, string Content);
public sealed record ChatRequest(List<ChatMessage>? Messages);

/// <summary>Loop agéntico sobre la Messages API de Claude con tool use.</summary>
public sealed class ClaudeAgent
{
    private readonly IHttpClientFactory _http;
    private readonly AgentTools _tools;
    private readonly ILogger<ClaudeAgent> _log;
    private readonly string? _apiKey;
    private readonly string _system;
    private readonly int _maxSteps;
    private readonly int _maxTokens;
    private readonly int _maxTokensCap;

    public string Model { get; }
    public bool HasApiKey => !string.IsNullOrWhiteSpace(_apiKey);

    public ClaudeAgent(IHttpClientFactory http, AgentTools tools, IConfiguration cfg, ILogger<ClaudeAgent> log)
    {
        _http = http; _tools = tools; _log = log;
        _apiKey = cfg["ANTHROPIC_API_KEY"]?.Trim().Trim('"', '\'').Trim();
        Model = cfg["CLAUDE_MODEL"] ?? "claude-sonnet-5-5";
        _maxSteps = int.TryParse(cfg["AGENT_MAX_STEPS"], out var s) ? s : 12;
        _maxTokens = int.TryParse(cfg["AGENT_MAX_TOKENS"], out var t) ? t : 16000;
        _maxTokensCap = Math.Max(_maxTokens, int.TryParse(cfg["AGENT_MAX_TOKENS_CAP"], out var c) ? c : 32000);
        _system = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "prompts", "system.md"));
    }

    public delegate Task Emit(string eventName, object data);

    public async Task RunAsync(IReadOnlyList<ChatMessage> history, Emit emit, CancellationToken ct)
    {
        if (!HasApiKey)
        {
            await emit("error", new { message = "El servidor no tiene configurada ANTHROPIC_API_KEY." });
            return;
        }

        var messages = BuildMessages(history);
        if (messages.Count == 0)
        {
            await emit("error", new { message = "No hay mensajes para procesar." });
            return;
        }

        long inTok = 0, outTok = 0, cacheRead = 0, cacheWrite = 0;
        var client = _http.CreateClient("anthropic");
        var curMax = _maxTokens;

        for (var step = 0; step < _maxSteps; step++)
        {
            var body = new JsonObject
            {
                ["model"] = Model,
                ["max_tokens"] = curMax,
                ["system"] = new JsonArray(new JsonObject
                {
                    ["type"] = "text",
                    ["text"] = _system,
                    ["cache_control"] = new JsonObject { ["type"] = "ephemeral" }
                }),
                ["tools"] = _tools.Definitions(),
                ["messages"] = messages.DeepClone(),
            };

            using var req = new HttpRequestMessage(HttpMethod.Post, "v1/messages");
            req.Headers.Add("x-api-key", _apiKey);
            req.Headers.Add("anthropic-version", "2023-06-01");
            req.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");

            HttpResponseMessage res;
            try { res = await client.SendAsync(req, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogError(ex, "Error llamando a la API de Claude");
                await emit("error", new { message = "No se pudo contactar la API de Claude.", detail = ex.Message });
                return;
            }

            using (res)
            {
                var raw = await res.Content.ReadAsStringAsync(ct);
                if (!res.IsSuccessStatusCode)
                {
                    _log.LogWarning("Claude API {Status}: {Body}", (int)res.StatusCode, Trunc(raw, 500));
                    await emit("error", new { message = $"La API de Claude respondió {(int)res.StatusCode}.", detail = Trunc(raw, 400) });
                    return;
                }

                var resp = JsonNode.Parse(raw)!;
                var usage = resp["usage"];
                inTok += Long(usage, "input_tokens");
                outTok += Long(usage, "output_tokens");
                cacheRead += Long(usage, "cache_read_input_tokens");
                cacheWrite += Long(usage, "cache_creation_input_tokens");

                var content = resp["content"]?.AsArray() ?? new JsonArray();
                var stop = resp["stop_reason"]?.GetValue<string>();

                // Si corta por límite de salida, se descarta la respuesta parcial y se reintenta
                // el mismo paso con más margen, hasta AGENT_MAX_TOKENS_CAP.
                if (stop == "max_tokens" && curMax < _maxTokensCap)
                {
                    curMax = Math.Min(_maxTokensCap, curMax * 2);
                    _log.LogInformation("max_tokens alcanzado; reintento con {Max}", curMax);
                    await emit("note", new { text = $"Respuesta extensa: reintentando con más margen ({curMax.ToString("N0").Replace(',', '.')} tokens)." });
                    step--;
                    continue;
                }

                messages.Add(new JsonObject { ["role"] = "assistant", ["content"] = content.DeepClone() });

                var text = string.Join("\n\n", content
                    .Where(b => Type(b) == "text")
                    .Select(b => b!["text"]!.GetValue<string>())
                    .Where(s => !string.IsNullOrWhiteSpace(s)));
                var toolUses = content.Where(b => Type(b) == "tool_use").ToList();

                if (stop != "tool_use" || toolUses.Count == 0)
                {
                    if (stop == "max_tokens") text += $"\n\n*(Respuesta cortada: superó el máximo de {_maxTokensCap.ToString("N0").Replace(',', '.')} tokens de salida.)*";
                    await emit("message", new { text, html = MarkdownLite.ToHtml(MarkdownLite.Parse(text)) });
                    await emit("done", new { usage = new { inputTokens = inTok, outputTokens = outTok, cacheReadTokens = cacheRead, cacheWriteTokens = cacheWrite }, steps = step + 1, model = Model });
                    return;
                }

                if (!string.IsNullOrWhiteSpace(text)) await emit("note", new { text });

                var results = new JsonArray();
                foreach (var tu in toolUses)
                {
                    var id = tu!["id"]!.GetValue<string>();
                    var name = tu["name"]!.GetValue<string>();
                    var input = tu["input"] ?? new JsonObject();

                    await emit("tool_start", new
                    {
                        id, name,
                        label = AgentTools.Labels.GetValueOrDefault(name, name),
                        input = JsonSerializer.Deserialize<JsonElement>(input.ToJsonString())
                    });

                    ToolResult r;
                    try { r = await _tools.ExecuteAsync(name, input, ct); }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _log.LogError(ex, "Error en herramienta {Tool}", name);
                        r = ToolResult.Error($"Falla interna en {name}: {ex.Message}");
                    }

                    await emit("tool_end", new { id, name, ok = !r.IsError, summary = r.Summary });
                    if (r.Document is { } doc)
                        await emit("document", new { id = doc.Id, title = doc.Title, docxUrl = $"/api/documents/{doc.Id}/docx", printUrl = $"/api/documents/{doc.Id}/print" });

                    var tr = new JsonObject { ["type"] = "tool_result", ["tool_use_id"] = id, ["content"] = r.Json };
                    if (r.IsError) tr["is_error"] = true;
                    results.Add(tr);
                }
                messages.Add(new JsonObject { ["role"] = "user", ["content"] = results });
            }
        }

        await emit("error", new { message = $"El agente alcanzó el máximo de {_maxSteps} pasos sin una respuesta final." });
    }

    /// <summary>Historial del cliente → mensajes válidos (empieza con user, roles alternados, tamaño acotado).</summary>
    private static JsonArray BuildMessages(IReadOnlyList<ChatMessage> history)
    {
        var arr = new JsonArray();
        string? lastRole = null;
        foreach (var m in history.TakeLast(24))
        {
            var role = m.Role == "assistant" ? "assistant" : "user";
            var content = (m.Content ?? "").Trim();
            if (content.Length == 0) continue;
            if (content.Length > 12000) content = content[..12000];
            if (arr.Count == 0 && role == "assistant") continue;
            if (role == lastRole)
            {
                var prev = arr[^1]!.AsObject();
                prev["content"] = prev["content"]!.GetValue<string>() + "\n\n" + content;
                continue;
            }
            arr.Add(new JsonObject { ["role"] = role, ["content"] = content });
            lastRole = role;
        }
        if (arr.Count > 0 && lastRole != "user") arr.RemoveAt(arr.Count - 1);
        return arr;
    }

    private static string? Type(JsonNode? b) => b?["type"]?.GetValue<string>();
    private static long Long(JsonNode? n, string k) => n?[k] is JsonValue v && v.TryGetValue<long>(out var l) ? l : 0;
    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}
