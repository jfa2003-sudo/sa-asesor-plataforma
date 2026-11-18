using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.RateLimiting;
using InfraAdvisor;

var builder = WebApplication.CreateBuilder(args);

// Render inyecta PORT. Local: 8080.
var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

var cfg = builder.Configuration;
var profilePath = cfg["PROFILE_PATH"] ?? Path.Combine(AppContext.BaseDirectory, "profile", "it-profile.json");

builder.Services.AddSingleton(_ => ProfileStore.Load(profilePath));
builder.Services.AddHttpClient("anthropic", c =>
{
    c.BaseAddress = new Uri(cfg["ANTHROPIC_BASE_URL"] ?? "https://api.anthropic.com/");
    c.Timeout = TimeSpan.FromMinutes(10); // respuestas largas sin streaming
});
builder.Services.AddHttpClient("azureprices", c => c.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddSingleton<AzurePricing>();
builder.Services.AddSingleton<PolicyValidator>();
builder.Services.AddSingleton<DocumentService>();
builder.Services.AddSingleton<AgentTools>();
builder.Services.AddSingleton<ClaudeAgent>();
builder.Services.AddHttpClient("npm", c => c.Timeout = TimeSpan.FromSeconds(60));
builder.Services.AddSingleton<InfraAdvisor.Security.SecurityScanner>();
builder.Services.AddSingleton<InfraAdvisor.Security.SecurityAgent>();

// Límite global de pedidos al agente (protege los tokens de la cuenta).
var perMinute = int.TryParse(cfg["CHAT_RATE_PER_MINUTE"], out var rpm) ? rpm : 10;
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddFixedWindowLimiter("chat", l =>
    {
        l.PermitLimit = perMinute;
        l.Window = TimeSpan.FromMinutes(1);
        l.QueueLimit = 0;
    });
    // Revisiones de seguridad: más caras, se limitan aparte.
    o.AddFixedWindowLimiter("review", l =>
    {
        l.PermitLimit = int.TryParse(cfg["REVIEW_RATE_PER_MINUTE"], out var r) ? r : 3;
        l.Window = TimeSpan.FromMinutes(1);
        l.QueueLimit = 0;
    });
});

var app = builder.Build();
var accessKey = cfg["ACCESS_KEY"]?.Trim();
var web = new JsonSerializerOptions(JsonSerializerDefaults.Web);

// Clave de acceso opcional para /api (excepto config y documentos, que usan id no adivinable).
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path;
    var open = !path.StartsWithSegments("/api")
               || path.StartsWithSegments("/api/config")
               || path.StartsWithSegments("/api/documents");
    if (!open && !string.IsNullOrEmpty(accessKey) && ctx.Request.Headers["X-Access-Key"] != accessKey)
    {
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await ctx.Response.WriteAsJsonAsync(new { error = "Clave de acceso inválida" });
        return;
    }
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseRateLimiter();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapGet("/api/config", (ClaudeAgent agent, ProfileStore p) => Results.Ok(new
{
    requiresKey = !string.IsNullOrEmpty(accessKey),
    model = agent.Model,
    apiKeyConfigured = agent.HasApiKey,
    profile = p.Root["meta"]
}));

app.MapGet("/api/profile", (ProfileStore p) => Results.Content(p.Raw, "application/json"));

// Respuesta en Server-Sent Events con keep-alive para proxies mientras el modelo trabaja.
async Task Sse(HttpContext ctx, Func<Func<string, object, Task>, Task> run)
{
    ctx.Response.Headers.ContentType = "text/event-stream";
    ctx.Response.Headers.CacheControl = "no-cache";
    ctx.Response.Headers["X-Accel-Buffering"] = "no";
    var gate = new SemaphoreSlim(1, 1);

    async Task Emit(string ev, object data)
    {
        await gate.WaitAsync();
        try
        {
            await ctx.Response.WriteAsync($"event: {ev}\ndata: {JsonSerializer.Serialize(data, web)}\n\n");
            await ctx.Response.Body.FlushAsync();
        }
        finally { gate.Release(); }
    }

    await ctx.Response.WriteAsync(": ok\n\n");
    await ctx.Response.Body.FlushAsync();

    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
    var ping = Task.Run(async () =>
    {
        try
        {
            while (!cts.IsCancellationRequested)
            {
                await Task.Delay(15000, cts.Token);
                await gate.WaitAsync(cts.Token);
                try { await ctx.Response.WriteAsync(": ping\n\n", cts.Token); await ctx.Response.Body.FlushAsync(cts.Token); }
                finally { gate.Release(); }
            }
        }
        catch (OperationCanceledException) { }
    });

    try { await run(Emit); }
    catch (OperationCanceledException) { }
    finally { cts.Cancel(); await ping; }
}

app.MapPost("/api/chat", async (HttpContext ctx, ChatRequest req, ClaudeAgent agent) =>
{
    if (req.Messages is null || req.Messages.Count == 0)
    {
        ctx.Response.StatusCode = 400;
        await ctx.Response.WriteAsJsonAsync(new { error = "messages vacío" });
        return;
    }
    await Sse(ctx, emit => agent.RunAsync(req.Messages, (ev, d) => emit(ev, d), ctx.RequestAborted));
}).RequireRateLimiting("chat");

app.MapGet("/api/security/profile", (InfraAdvisor.Security.SecurityAgent sec) => Results.Content(sec.ProfileRaw, "application/json"));

app.MapPost("/api/security/review", async (HttpContext ctx, InfraAdvisor.Security.SecurityScanner scanner, InfraAdvisor.Security.SecurityAgent agent, ILogger<Program> log) =>
{
    IFormCollection form;
    try { form = await ctx.Request.ReadFormAsync(ctx.RequestAborted); }
    catch (Exception ex) when (ex is InvalidDataException or BadHttpRequestException or IOException)
    {
        ctx.Response.StatusCode = 400;
        await ctx.Response.WriteAsJsonAsync(new { error = "No se pudo leer el envío. ¿El zip supera los 30 MB?" });
        return;
    }
    var code = form.Files["code"];
    if (code is null || code.Length == 0 || !code.FileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
    {
        ctx.Response.StatusCode = 400;
        await ctx.Response.WriteAsJsonAsync(new { error = "Falta el código en un archivo .zip." });
        return;
    }
    if (code.Length > InfraAdvisor.Security.CodeRepo.MaxZipBytes)
    {
        ctx.Response.StatusCode = 400;
        await ctx.Response.WriteAsJsonAsync(new { error = "El zip supera los 30 MB. Sacá node_modules, bin, obj y archivos de build." });
        return;
    }
    var arch = form.Files["arch"];
    var requester = form["requester"].ToString().Trim();

    await Sse(ctx, async emit =>
    {
        InfraAdvisor.Security.CodeRepo repo;
        string? archText = null;
        await emit("tool_start", new { id = "zip", name = "zip", label = "Leyendo el código del zip" });
        try
        {
            using var ms = new MemoryStream();
            await using (var s = code.OpenReadStream()) await s.CopyToAsync(ms, ctx.RequestAborted);
            ms.Position = 0;
            repo = InfraAdvisor.Security.CodeRepo.Load(ms);
            if (arch is not null && arch.Length > 0)
            {
                await using var a = arch.OpenReadStream();
                archText = InfraAdvisor.Security.DocText.Extract(a, arch.FileName);
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            await emit("tool_end", new { id = "zip", name = "zip", ok = false, summary = ex.Message });
            await emit("error", new { message = ex.Message });
            return;
        }
        await emit("tool_end", new { id = "zip", name = "zip", ok = true, summary = $"{repo.AllPaths.Count} archivos, {repo.Files.Count} de texto" + (archText is null ? "" : " · documento de arquitectura leído") });

        await emit("tool_start", new { id = "scan", name = "scan", label = "Chequeos automáticos: secretos, dependencias, Dockerfile, CI, IaC, TLS" });
        var scan = await scanner.ScanAsync(repo, ctx.RequestAborted);
        var flagged = scan.Signals.Count(x => x.Severity is "alta" or "media");
        await emit("tool_end", new { id = "scan", name = "scan", ok = true, summary = $"{flagged} señales a revisar · {scan.Vulnerabilities.Count} avisos de dependencias" });

        await agent.RunAsync(new InfraAdvisor.Security.ReviewInput(repo, scan, code.FileName, archText, arch?.FileName, requester.Length > 0 ? requester : null),
            (ev, d) => emit(ev, d), ctx.RequestAborted);
    });
}).RequireRateLimiting("review").WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(40L * 1024 * 1024));

app.MapGet("/api/documents/{id}/docx", (string id, DocumentService docs) =>
{
    var d = docs.Get(id);
    if (d is null) return Results.NotFound(new { error = "Documento no encontrado o vencido" });
    var file = string.Concat(d.Title.Select(c => char.IsLetterOrDigit(c) || c is ' ' or '-' ? c : '_')).Trim();
    return Results.File(docs.ToDocx(d),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        $"{(file.Length > 0 ? file : "recomendacion")}.docx");
});

app.MapGet("/api/documents/{id}/print", (string id, DocumentService docs) =>
{
    var d = docs.Get(id);
    return d is null ? Results.NotFound("Documento no encontrado o vencido") : Results.Content(docs.ToPrintHtml(d), "text/html; charset=utf-8");
});

// Solo en Development: ejecutar herramientas sin pasar por el modelo (útil para probar el perfil).
if (app.Environment.IsDevelopment())
{
    app.MapPost("/api/dev/tools/{name}", async (string name, HttpContext ctx, AgentTools tools) =>
    {
        var input = await JsonNode.ParseAsync(ctx.Request.Body) ?? new JsonObject();
        var r = await tools.ExecuteAsync(name, input, ctx.RequestAborted);
        return Results.Content(r.Json, "application/json", statusCode: r.IsError ? 400 : 200);
    });

    app.MapPost("/api/dev/scan", async (HttpContext ctx, InfraAdvisor.Security.SecurityScanner scanner) =>
    {
        var form = await ctx.Request.ReadFormAsync();
        var file = form.Files["code"];
        if (file is null) return Results.BadRequest();
        await using var s = file.OpenReadStream();
        var repo = InfraAdvisor.Security.CodeRepo.Load(s);
        var r = await scanner.ScanAsync(repo, ctx.RequestAborted);
        return Results.Content(r.ToJson().ToJsonString(new JsonSerializerOptions { WriteIndented = true }), "application/json");
    }).DisableAntiforgery();
}

app.Run();
