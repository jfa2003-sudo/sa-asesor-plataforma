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

app.MapPost("/api/chat", async (HttpContext ctx, ChatRequest req, ClaudeAgent agent) =>
{
    if (req.Messages is null || req.Messages.Count == 0)
    {
        ctx.Response.StatusCode = 400;
        await ctx.Response.WriteAsJsonAsync(new { error = "messages vacío" });
        return;
    }

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

    // Keep-alive para proxies mientras el modelo piensa.
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

    try { await agent.RunAsync(req.Messages, Emit, ctx.RequestAborted); }
    catch (OperationCanceledException) { }
    finally { cts.Cancel(); await ping; }
}).RequireRateLimiting("chat");

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
}

app.Run();
