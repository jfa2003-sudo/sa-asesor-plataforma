using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json.Nodes;

namespace InfraAdvisor;

/// <summary>
/// Consulta la Azure Retail Prices API (pública, sin autenticación).
/// Doc: https://learn.microsoft.com/rest/api/cost-management/retail-prices/azure-retail-prices
/// </summary>
public sealed class AzurePricing
{
    private readonly IHttpClientFactory _http;
    private readonly ProfileStore _profile;
    private readonly string _baseUrl;
    private readonly ConcurrentDictionary<string, (DateTime at, JsonObject result)> _cache = new();
    private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(6);
    private const int MaxPages = 3;      // 1.000 ítems por página según la API
    private const int MaxItemsOut = 15;  // lo que se devuelve al agente

    public AzurePricing(IHttpClientFactory http, ProfileStore profile, IConfiguration cfg)
    {
        _http = http;
        _profile = profile;
        _baseUrl = cfg["AZURE_PRICES_URL"] ?? "https://prices.azure.com/api/retail/prices";
    }

    public async Task<ToolResult> LookupAsync(JsonNode input, CancellationToken ct)
    {
        string? Str(string k) => input[k]?.GetValue<string>()?.Trim() is { Length: > 0 } s ? s : null;

        var service = Str("serviceName");
        var region = Str("armRegionName") ?? _profile.PrimaryRegion;
        if (service is null) return ToolResult.Error("Falta serviceName (ej: 'Virtual Machines').");

        if (!_profile.AllowedRegions.Contains(region))
            return ToolResult.Error($"La región '{region}' no está permitida por el perfil de IT. Permitidas: {string.Join(", ", _profile.AllowedRegions)}.");

        var sku = Str("armSkuName");
        var productContains = Str("productNameContains");
        var skuContains = Str("skuNameContains");
        var meterContains = Str("meterNameContains");
        var os = Str("os")?.ToLowerInvariant();
        var includeSpot = input["includeSpot"]?.GetValue<bool>() ?? false;

        var filter = new List<string>
        {
            $"serviceName eq '{Esc(service)}'",
            $"armRegionName eq '{Esc(region)}'",
            "priceType eq 'Consumption'"
        };
        if (sku is not null) filter.Add($"armSkuName eq '{Esc(sku)}'");
        if (productContains is not null) filter.Add($"contains(productName, '{Esc(productContains)}')");
        if (skuContains is not null) filter.Add($"contains(skuName, '{Esc(skuContains)}')");
        if (meterContains is not null) filter.Add($"contains(meterName, '{Esc(meterContains)}')");
        var filterText = string.Join(" and ", filter);

        var cacheKey = $"{filterText}|{os}|{includeSpot}";
        if (_cache.TryGetValue(cacheKey, out var hit) && DateTime.UtcNow - hit.at < CacheTtl)
            return ToolResult.Ok(hit.result, Summary(hit.result));

        var url = $"{_baseUrl}?api-version=2023-01-01-preview&meterRegion='primary'&currencyCode='USD'&$filter={Uri.EscapeDataString(filterText)}";
        var client = _http.CreateClient("azureprices");
        var items = new List<JsonObject>();
        string? next = url;
        for (var page = 0; page < MaxPages && next is not null; page++)
        {
            using var res = await client.GetAsync(next, ct);
            var body = await res.Content.ReadAsStringAsync(ct);
            if (!res.IsSuccessStatusCode)
                return ToolResult.Error($"Azure Retail Prices API respondió {(int)res.StatusCode}: {Trunc(body, 300)}");
            var json = JsonNode.Parse(body)!;
            foreach (var it in json["Items"]?.AsArray() ?? new JsonArray())
                if (it is JsonObject o) items.Add(o);
            next = json["NextPageLink"]?.GetValue<string>();
        }

        var hours = _profile.HoursPerMonth;
        var filtered = items
            .Where(i => includeSpot || !(S(i, "meterName").Contains("Spot") || S(i, "meterName").Contains("Low Priority")))
            .Where(i => os switch
            {
                "windows" => S(i, "productName").Contains("Windows"),
                "linux" => !S(i, "productName").Contains("Windows"),
                _ => true
            })
            .OrderBy(i => D(i, "retailPrice"))
            .ToList();

        var outItems = new JsonArray();
        foreach (var i in filtered.Take(MaxItemsOut))
        {
            var price = D(i, "retailPrice");
            var unit = S(i, "unitOfMeasure");
            var o = new JsonObject
            {
                ["productName"] = S(i, "productName"),
                ["skuName"] = S(i, "skuName"),
                ["armSkuName"] = S(i, "armSkuName"),
                ["meterName"] = S(i, "meterName"),
                ["unitOfMeasure"] = unit,
                ["retailPriceUsd"] = price,
            };
            if (unit == "1 Hour") o["monthlyUsd"] = Math.Round(price * hours, 2);
            if (i["savingsPlan"] is JsonArray sp && sp.Count > 0)
            {
                var spOut = new JsonArray();
                foreach (var s in sp)
                {
                    var spPrice = s?["retailPrice"]?.GetValue<double>() ?? 0;
                    var spo = new JsonObject { ["term"] = s?["term"]?.GetValue<string>(), ["retailPriceUsd"] = spPrice };
                    if (unit == "1 Hour") spo["monthlyUsd"] = Math.Round(spPrice * hours, 2);
                    spOut.Add(spo);
                }
                o["savingsPlan"] = spOut;
            }
            outItems.Add(o);
        }

        var result = new JsonObject
        {
            ["source"] = "Azure Retail Prices API (precios de lista, USD, sin descuentos ni impuestos)",
            ["queriedAtUtc"] = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture),
            ["filter"] = filterText,
            ["osFilter"] = os ?? "ninguno",
            ["hoursPerMonth"] = hours,
            ["totalMatches"] = filtered.Count,
            ["items"] = outItems,
        };
        if (filtered.Count == 0)
            result["hint"] = "Sin resultados. Revisá mayúsculas exactas de serviceName/armSkuName o probá con productNameContains/skuNameContains.";

        _cache[cacheKey] = (DateTime.UtcNow, result);
        return ToolResult.Ok(result, Summary(result));
    }

    private static string Summary(JsonObject r)
    {
        var n = r["totalMatches"]?.GetValue<int>() ?? 0;
        if (n == 0) return "Sin resultados";
        var first = r["items"]![0]!;
        var monthly = first["monthlyUsd"]?.GetValue<double>();
        return $"{n} precios · desde {first["armSkuName"] ?? first["skuName"]}" +
               (monthly is not null ? $" USD {monthly:0.00}/mes" : $" USD {first["retailPriceUsd"]}/{first["unitOfMeasure"]}");
    }

    private static string Esc(string s) => s.Replace("'", "''");
    private static string S(JsonObject o, string k) => o[k]?.GetValue<string>() ?? "";
    private static double D(JsonObject o, string k) => o[k]?.GetValue<double>() ?? 0;
    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}
