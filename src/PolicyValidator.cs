using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace InfraAdvisor;

/// <summary>Validación determinística de una propuesta contra el perfil de IT. No usa el modelo.</summary>
public sealed class PolicyValidator
{
    private readonly ProfileStore _p;
    public PolicyValidator(ProfileStore profile) => _p = profile;

    private sealed record Check(string Area, string Rule, string Status, string Detail);

    public ToolResult Validate(JsonNode input)
    {
        var checks = new List<Check>();
        var area = "General";
        void Ok(string r, string d) => checks.Add(new(area, r, "ok", d));
        void Warn(string r, string d) => checks.Add(new(area, r, "warn", d));
        void Fail(string r, string d) => checks.Add(new(area, r, "fail", d));

        var root = _p.Root;
        var envName = Str(input, "environment")?.ToLowerInvariant() ?? "";
        var critName = Str(input, "criticality")?.ToLowerInvariant() ?? "";
        var sizeName = Str(input, "appSize")?.ToLowerInvariant();
        var devType = Str(input, "developmentType")?.ToLowerInvariant() ?? "propio";
        var region = Str(input, "region") ?? _p.PrimaryRegion;
        var drRegion = Str(input, "drRegion");
        var components = input["components"] as JsonArray ?? new JsonArray();
        var tags = input["tags"] as JsonObject ?? new JsonObject();
        var comps = components.OfType<JsonObject>().ToList();
        List<JsonObject> OfKind(params string[] kinds) => comps.Where(c => kinds.Contains(Str(c, "kind")?.ToLowerInvariant())).ToList();

        // ---------- General ----------
        var env = _p.Environment(envName);
        if (env is null) Fail("Ambiente", $"'{envName}' no existe en el perfil. Válidos: {string.Join(", ", _p.EnvironmentNames)}");
        else Ok("Ambiente", envName);

        var crit = _p.Criticality(critName);
        if (crit is null) Fail("Criticidad", $"'{critName}' no existe en el perfil. Válidas: {string.Join(", ", _p.CriticalityNames)}");
        else Ok("Criticidad", $"{critName} (RPO {crit["rpoHours"]} h, RTO {crit["rtoHours"]} h)");

        var sizes = root["appSizing"]?["classes"] as JsonObject;
        if (sizes is not null)
        {
            if (sizeName is null) Warn("Tamaño de aplicación", $"No informado. Válidos: {string.Join(", ", sizes.Select(s => s.Key))}");
            else if (sizes[sizeName] is null) Fail("Tamaño de aplicación", $"'{sizeName}' no existe. Válidos: {string.Join(", ", sizes.Select(s => s.Key))}");
            else Ok("Tamaño de aplicación", sizeName);
        }

        if (_p.AllowedRegions.Contains(region)) Ok("Región", region);
        else Fail("Región", $"'{region}' fuera de las permitidas ({string.Join(", ", _p.AllowedRegions)})");

        if (components.Count == 0) Fail("Componentes", "La propuesta no tiene componentes");

        // ---------- Cómputo ----------
        area = "Cómputo";
        var allowedSeries = Arr(env, "allowedVmSeries").Select(s => s.ToUpperInvariant()).ToHashSet();
        var maxVcpu = env?["maxVcpuPerVm"]?.GetValue<int>();
        var allowPublicIp = env?["allowPublicIp"]?.GetValue<bool>() ?? true;
        var preferredOs = root["standards"]?["preferredOs"]?.GetValue<string>();
        var requireAz = crit?["requireAvailabilityZones"]?.GetValue<bool>() ?? false;
        var requireBackup = crit?["requireBackup"]?.GetValue<bool>() ?? false;
        var minInstances = crit?["minComputeInstances"]?.GetValue<int>() ?? 1;
        var requireDr = crit?["requireDrRegion"]?.GetValue<bool>() ?? false;

        foreach (var c in OfKind("vm"))
        {
            var name = Str(c, "name") ?? "vm";
            var sku = Str(c, "sku") ?? "";
            var m = Regex.Match(sku, @"^Standard_([A-Za-z]+)(\d+)");
            if (!m.Success) Warn($"Serie VM · {name}", $"No se pudo interpretar el SKU '{sku}'");
            else
            {
                var series = m.Groups[1].Value[..1].ToUpperInvariant();
                var vcpu = int.Parse(m.Groups[2].Value);
                if (allowedSeries.Count > 0 && !allowedSeries.Contains(series))
                    Fail($"Serie VM · {name}", $"Serie {series} no permitida en {envName} (permitidas: {string.Join(", ", allowedSeries)})");
                else Ok($"Serie VM · {name}", $"{sku} (serie {series})");
                if (maxVcpu is not null && vcpu > maxVcpu)
                    Fail($"vCPU · {name}", $"{vcpu} vCPU supera el máximo de {maxVcpu} para {envName}");
            }
            var os = Str(c, "os")?.ToLowerInvariant();
            if (preferredOs is not null && os is not null && os != preferredOs)
                Warn($"Sistema operativo · {name}", $"{os} no es el preferido ({preferredOs}); justificar");
            if (Bool(c, "publicIp") == true && !allowPublicIp)
                Fail($"IP pública · {name}", $"No permitida en {envName}");
        }

        var computeInstances = OfKind("vm", "compute").Sum(c => Math.Max(1, (int)(Num(c, "quantity") ?? 1)));
        if (computeInstances > 0)
        {
            if (computeInstances < minInstances)
                Fail("Instancias de cómputo", $"{computeInstances} instancia(s); la criticidad {critName} exige mínimo {minInstances}");
            else Ok("Instancias de cómputo", $"{computeInstances} (mínimo {minInstances})");
        }

        foreach (var c in OfKind("vm", "database"))
        {
            var name = Str(c, "name") ?? "componente";
            if (requireAz && Bool(c, "availabilityZones") != true)
                Fail($"Zonas de disponibilidad · {name}", $"La criticidad {critName} exige despliegue zonal");
            if (requireBackup && Bool(c, "backupEnabled") != true)
                Fail($"Backup · {name}", $"La criticidad {critName} exige backup");
        }

        if (requireDr)
        {
            if (drRegion is null) Fail("DR", $"La criticidad {critName} exige región de DR ({_p.DrRegion})");
            else if (drRegion != _p.DrRegion) Fail("DR", $"La región de DR debe ser {_p.DrRegion}");
            else Ok("DR", drRegion);
        }

        // ---------- Base de datos ----------
        area = "Base de datos";
        var dbCfg = root["databases"] as JsonObject;
        var engines = dbCfg?["engines"] as JsonObject;
        var sizing = sizeName is null ? null : dbCfg?["sizing"]?[sizeName];
        var dbPeEnvs = Arr(dbCfg, "privateEndpointIn");
        foreach (var c in OfKind("database"))
        {
            var name = Str(c, "name") ?? "base de datos";
            var engine = Str(c, "engine")?.ToLowerInvariant();
            if (engine is null) Warn($"Motor · {name}", "Motor no informado");
            else if (engines?[engine] is not JsonObject e) Fail($"Motor · {name}", $"'{engine}' no aprobado. Aprobados: {string.Join(", ", engines?.Select(x => x.Key) ?? [])}");
            else if (e["requiresApproval"]?.GetValue<bool>() == true) Fail($"Motor · {name}", $"{e["label"]} requiere aprobación de IT ({e["useWhen"]})");
            else Ok($"Motor · {name}", e["label"]!.GetValue<string>());

            var tier = Norm(Str(c, "tier"));
            var allowedTiers = Arr(sizing, "allowedTiers");
            if (sizing is not null)
            {
                if (tier.Length == 0) Warn($"Tier · {name}", $"Tier no informado. Para app {sizeName}: {string.Join(", ", allowedTiers)}");
                else if (!allowedTiers.Select(Norm).Contains(tier))
                    Fail($"Tier · {name}", $"'{Str(c, "tier")}' no corresponde a una app {sizeName} (permitidos: {string.Join(", ", allowedTiers)})");
                else Ok($"Tier · {name}", Str(c, "tier")!);

                var minRet = sizing["backupRetentionDays"]?.GetValue<int>();
                var ret = Num(c, "backupRetentionDays");
                if (minRet is not null && ret is not null && ret < minRet)
                    Fail($"Retención de backup · {name}", $"{ret} días; mínimo {minRet} para app {sizeName}");

                if (sizing["readReplica"]?.GetValue<bool>() == true && Bool(c, "readReplica") != true)
                    Warn($"Réplica de lectura · {name}", $"Recomendada para app {sizeName}");
            }

            if (dbPeEnvs.Contains(envName) && Bool(c, "privateEndpoint") != true)
                Fail($"Private endpoint · {name}", $"Obligatorio en {envName}");
        }

        // ---------- Stack ----------
        area = "Stack";
        var stackCfg = root["platformStack"] as JsonObject;
        var stack = input["stack"] as JsonObject;
        if (stackCfg is not null && stack is not null)
        {
            if (devType == "tercero")
                Ok("Lenguajes", "Producto de terceros: el stack no se valida contra los lineamientos de desarrollo propio");
            else foreach (var (layer, val) in stack)
            {
                var id = val?.GetValue<string>()?.Trim().ToLowerInvariant();
                if (string.IsNullOrEmpty(id) || id == "no-aplica") continue;
                if (stackCfg[layer] is not JsonObject lc) { Warn($"Capa {layer}", "Capa no definida en el perfil"); continue; }
                var label = lc["label"]?.GetValue<string>() ?? layer;
                string? Find(string list) => (lc[list] as JsonArray)?.OfType<JsonObject>()
                    .FirstOrDefault(o => o["id"]?.GetValue<string>() == id)?["label"]?.GetValue<string>();
                if (Find("preferred") is { } p) Ok(label, $"{p} (preferido)");
                else if (Find("allowed") is { } a) Ok(label, $"{a} (permitido)");
                else if (Find("requiresApproval") is { } r) Fail(label, $"{r} requiere aprobación de IT");
                else
                {
                    var opts = new[] { "preferred", "allowed" }.SelectMany(l => (lc[l] as JsonArray)?.OfType<JsonObject>() ?? [])
                        .Select(o => o["id"]?.GetValue<string>());
                    Fail(label, $"'{id}' no está en los lineamientos (opciones: {string.Join(", ", opts)})");
                }
            }
        }

        // ---------- API Management ----------
        area = "API Management";
        var apimCfg = root["apiManagement"] as JsonObject;
        var consumers = (input["apiConsumers"] as JsonArray)?.Select(n => n?.GetValue<string>()?.ToLowerInvariant() ?? "").ToList() ?? new();
        var requiredFor = apimCfg?["requiredFor"] as JsonObject;
        var triggers = consumers.Where(cn => requiredFor?[cn] is not null).ToList();
        var apims = OfKind("apim");
        var sharedApim = Bool(input, "useSharedApim") == true;
        if (triggers.Count > 0)
        {
            var why = string.Join("; ", triggers.Select(t => requiredFor![t]!.GetValue<string>()));
            if (apims.Count == 0 && !sharedApim) Fail("Publicación de API", $"Requiere API Management: {why}");
            else Ok("Publicación de API", sharedApim ? $"Instancia compartida de IT ({why})" : $"Instancia propia ({why})");
        }
        var apimTiers = Arr(apimCfg?["tiersByEnvironment"], envName);
        foreach (var c in apims)
        {
            var tier = Str(c, "tier") ?? Str(c, "sku") ?? "";
            if (apimTiers.Count > 0 && !apimTiers.Select(Norm).Contains(Norm(tier)))
                Fail($"Tier APIM · {Str(c, "name") ?? "apim"}", $"'{tier}' no permitido en {envName} (permitidos: {string.Join(", ", apimTiers)})");
            else Ok($"Tier APIM · {Str(c, "name") ?? "apim"}", tier);
            if (apimCfg?["model"] is not null && !sharedApim)
                Warn("Modelo APIM", $"El perfil indica: {apimCfg["model"]}. Justificar instancia propia.");
        }

        // ---------- Secretos ----------
        area = "Secretos";
        var sec = root["secrets"] as JsonObject;
        var kvs = OfKind("keyvault");
        if (sec?["required"]?.GetValue<bool>() == true)
        {
            if (kvs.Count == 0) Fail("Key Vault", $"Obligatorio: {sec["model"]}");
            else Ok("Key Vault", $"{kvs.Count} instancia(s)");
        }
        var purgeEnvs = Arr(sec, "purgeProtectionIn");
        var kvPeEnvs = Arr(sec, "privateEndpointIn");
        foreach (var c in kvs)
        {
            var name = Str(c, "name") ?? "key vault";
            var tier = Str(c, "tier") ?? "Standard";
            if (Norm(tier) == "premium" && sec?["premiumRequiresApproval"]?.GetValue<bool>() == true)
                Fail($"Tier · {name}", "Premium (HSM) requiere aprobación de IT");
            if (purgeEnvs.Contains(envName) && Bool(c, "purgeProtection") != true)
                Fail($"Purge protection · {name}", $"Obligatoria en {envName}");
            if (kvPeEnvs.Contains(envName) && Bool(c, "privateEndpoint") != true)
                Fail($"Private endpoint · {name}", $"Obligatorio en {envName}");
        }

        // ---------- Gobierno y costo ----------
        area = "Gobierno y costo";
        var missingTags = _p.RequiredTags
            .Where(t => tags[t] is not JsonValue v || string.IsNullOrWhiteSpace(v.ToString()))
            .ToArray();
        if (missingTags.Length > 0) Warn("Tags", $"Faltan: {string.Join(", ", missingTags)}");
        else Ok("Tags", "Completos");

        double total = 0;
        var costLines = new JsonArray();
        foreach (var c in comps)
        {
            var name = Str(c, "name") ?? Str(c, "kind") ?? "componente";
            var qty = Math.Max(1, (int)(Num(c, "quantity") ?? 1));
            var monthly = Num(c, "monthlyUsd");
            var hourly = Num(c, "hourlyUsd");
            var hours = Num(c, "hoursPerMonth") ?? _p.HoursPerMonth;
            double? unitMonthly = monthly ?? (hourly is not null ? hourly * hours : null);
            if (unitMonthly is null)
            {
                if (Bool(c, "sharedCost") != true) Warn($"Costo · {name}", "Sin precio informado: el total queda subestimado");
                continue;
            }
            var line = Math.Round(unitMonthly.Value * qty, 2);
            total += line;
            costLines.Add(new JsonObject { ["component"] = name, ["sku"] = Str(c, "sku") ?? Str(c, "tier") ?? "", ["quantity"] = qty, ["monthlyUsd"] = line });
        }
        total = Math.Round(total, 2);

        var budget = env?["maxMonthlyUsd"]?.GetValue<double>();
        if (budget is not null)
        {
            if (total > budget) Fail("Presupuesto", $"USD {total:0.00}/mes supera el tope de {envName} (USD {budget:0})");
            else if (total > budget * 0.8) Warn("Presupuesto", $"USD {total:0.00}/mes usa más del 80% del tope (USD {budget:0})");
            else Ok("Presupuesto", $"USD {total:0.00}/mes de USD {budget:0}");
        }

        var verdict = checks.Any(c => c.Status == "fail") ? "REQUIERE_EXCEPCION"
                    : checks.Any(c => c.Status == "warn") ? "APROBADO_CON_OBSERVACIONES"
                    : "APROBADO";

        var result = new JsonObject
        {
            ["verdict"] = verdict,
            ["totalMonthlyUsd"] = total,
            ["budgetMonthlyUsd"] = budget,
            ["commitmentGuideline"] = env?["commitment"]?.GetValue<string>(),
            ["databaseSizingGuideline"] = sizing?.DeepClone(),
            ["costBreakdown"] = costLines,
            ["checks"] = new JsonArray(checks.Select(c => (JsonNode)new JsonObject
            {
                ["area"] = c.Area, ["rule"] = c.Rule, ["status"] = c.Status, ["detail"] = c.Detail
            }).ToArray()),
        };

        var fails = checks.Count(c => c.Status == "fail");
        var warns = checks.Count(c => c.Status == "warn");
        return ToolResult.Ok(result, $"{verdict} · USD {total:0.00}/mes · {fails} incumplimientos, {warns} observaciones");
    }

    private static string? Str(JsonNode? n, string k) =>
        n?[k] is JsonValue v && v.TryGetValue<string>(out var s) && !string.IsNullOrWhiteSpace(s) ? s.Trim() : null;
    private static bool? Bool(JsonNode? n, string k) => n?[k] is JsonValue v && v.TryGetValue<bool>(out var b) ? b : null;
    private static double? Num(JsonNode? n, string k) => n?[k] is JsonValue v && v.TryGetValue<double>(out var d) ? d : null;
    private static List<string> Arr(JsonNode? n, string k) =>
        (n?[k] as JsonArray)?.Select(x => x?.GetValue<string>() ?? "").ToList() ?? new();
    private static string Norm(string? s) => Regex.Replace(s ?? "", @"[\s_\-]", "").ToLowerInvariant();
}
