using System.Text.Json.Nodes;

namespace InfraAdvisor;

public sealed record ToolResult(string Json, string Summary, bool IsError)
{
    public RecommendationDoc? Document { get; init; }
    public static ToolResult Ok(JsonNode data, string summary) => new(data.ToJsonString(), summary, false);
    public static ToolResult Error(string message) => new(new JsonObject { ["error"] = message }.ToJsonString(), message, true);
}

/// <summary>Herramientas que el agente puede usar. Definición (JSON Schema) + ejecución.</summary>
public sealed class AgentTools
{
    private readonly ProfileStore _profile;
    private readonly AzurePricing _pricing;
    private readonly PolicyValidator _validator;
    private readonly DocumentService _docs;

    public AgentTools(ProfileStore profile, AzurePricing pricing, PolicyValidator validator, DocumentService docs)
    {
        _profile = profile; _pricing = pricing; _validator = validator; _docs = docs;
    }

    public static readonly Dictionary<string, string> Labels = new()
    {
        ["get_it_profile"] = "Leyendo el perfil de plataforma de IT",
        ["azure_price_lookup"] = "Consultando precios de Azure",
        ["validate_proposal"] = "Validando la propuesta contra el perfil",
        ["create_recommendation_document"] = "Generando el documento de recomendación",
    };

    private const string DefinitionsJson = """
[
  {
    "name": "get_it_profile",
    "description": "Devuelve el perfil de plataforma definido por IT: regiones permitidas, ambientes con topes de costo y series de VM, niveles de criticidad (RPO/RTO, alta disponibilidad, backup, DR), servicios aprobados y prohibidos, tags y naming. Usalo antes de recomendar.",
    "input_schema": { "type": "object", "properties": {}, "additionalProperties": false }
  },
  {
    "name": "azure_price_lookup",
    "description": "Consulta precios de lista de Azure (Retail Prices API, USD, consumo). Devuelve hasta 15 ítems ordenados por precio, con costo mensual estimado para precios por hora y precios de savings plan cuando existen. Los valores distinguen mayúsculas. Solo regiones permitidas por el perfil.",
    "input_schema": {
      "type": "object",
      "properties": {
        "serviceName": { "type": "string", "description": "Nombre exacto del servicio, ej: 'Virtual Machines', 'SQL Database', 'Azure Database for PostgreSQL', 'Azure Database for MySQL', 'Azure App Service', 'Azure Container Apps', 'Functions', 'Storage', 'API Management', 'Key Vault'. Para bases usá databases.engines.<motor>.priceServiceName del perfil." },
        "armRegionName": { "type": "string", "description": "Región ARM, ej: 'brazilsouth'. Por defecto, la primaria del perfil." },
        "armSkuName": { "type": "string", "description": "SKU ARM exacto, ej: 'Standard_D4s_v5'. Opcional." },
        "productNameContains": { "type": "string", "description": "Texto contenido en productName, ej: 'Premium SSD', 'General Purpose', 'Flexible Server'." },
        "skuNameContains": { "type": "string", "description": "Texto contenido en skuName, ej: 'P1v3', 'vCore'." },
        "meterNameContains": { "type": "string", "description": "Texto contenido en meterName." },
        "os": { "type": "string", "enum": ["linux", "windows"], "description": "Solo para Virtual Machines." },
        "includeSpot": { "type": "boolean", "description": "Incluir precios Spot/Low Priority. Por defecto false." }
      },
      "required": ["serviceName"],
      "additionalProperties": false
    }
  },
  {
    "name": "validate_proposal",
    "description": "Valida de forma determinística una propuesta contra el perfil de IT: región, tamaño de app, series y vCPU de VM, IP pública, zonas, backup, DR, instancias mínimas, motor/tier/retención/private endpoint de base de datos, lenguajes por capa, API Management, Key Vault, tags y tope de costo mensual. Devuelve veredicto, costo total y detalle por área y regla.",
    "input_schema": {
      "type": "object",
      "properties": {
        "environment": { "type": "string", "description": "dev | qa | prod (según perfil)" },
        "criticality": { "type": "string", "description": "baja | media | alta | critica (según perfil)" },
        "appSize": { "type": "string", "description": "Clase de appSizing del perfil: chica | mediana | grande" },
        "developmentType": { "type": "string", "enum": ["propio", "tercero"], "description": "Desarrollo propio o producto de terceros (ej. Moodle)." },
        "region": { "type": "string" },
        "drRegion": { "type": "string", "description": "Región de DR, si aplica." },
        "stack": {
          "type": "object",
          "description": "Ids de platformStack por capa. Omitir capas que no aplican.",
          "properties": {
            "frontendWeb": { "type": "string" },
            "backend": { "type": "string" },
            "mobile": { "type": "string" }
          }
        },
        "apiConsumers": { "type": "array", "items": { "type": "string" }, "description": "Quién consume la API: claves de apiManagement.requiredFor (mobile, terceros, otras_apps) o 'interna'." },
        "useSharedApim": { "type": "boolean", "description": "true si se publica en la instancia compartida de APIM administrada por IT." },
        "components": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "kind": { "type": "string", "enum": ["vm", "compute", "database", "storage", "apim", "keyvault", "network", "monitoring", "other"], "description": "'vm' para máquinas virtuales; 'compute' para PaaS de cómputo (App Service, Container Apps, Functions, Static Web Apps)." },
              "name": { "type": "string" },
              "service": { "type": "string" },
              "sku": { "type": "string", "description": "Para VMs, el armSkuName, ej: Standard_D4s_v5." },
              "tier": { "type": "string", "description": "Base de datos: Burstable | GeneralPurpose | MemoryOptimized | BusinessCritical. APIM: Developer | Consumption | Basic v2 | Standard v2. Key Vault: Standard | Premium." },
              "engine": { "type": "string", "description": "Solo base de datos: clave de databases.engines (postgresql, sqlserver, mysql, cosmosdb)." },
              "quantity": { "type": "integer", "minimum": 1 },
              "hourlyUsd": { "type": "number", "description": "Precio por hora por unidad (de azure_price_lookup)." },
              "hoursPerMonth": { "type": "number", "description": "Horas de uso al mes; por defecto las del perfil." },
              "monthlyUsd": { "type": "number", "description": "Costo mensual por unidad, si el precio no es por hora." },
              "sharedCost": { "type": "boolean", "description": "true si el costo lo absorbe un servicio compartido de IT (no se suma)." },
              "os": { "type": "string", "enum": ["linux", "windows"] },
              "availabilityZones": { "type": "boolean" },
              "backupEnabled": { "type": "boolean" },
              "backupRetentionDays": { "type": "number" },
              "readReplica": { "type": "boolean" },
              "privateEndpoint": { "type": "boolean" },
              "purgeProtection": { "type": "boolean", "description": "Solo Key Vault." },
              "publicIp": { "type": "boolean" }
            },
            "required": ["kind", "name", "quantity"]
          }
        },
        "tags": { "type": "object", "description": "Tags propuestos, ej: {\"Application\":\"moodle\",\"Environment\":\"prod\"}", "additionalProperties": { "type": "string" } }
      },
      "required": ["environment", "criticality", "appSize", "components"]
    }
  },
  {
    "name": "create_recommendation_document",
    "description": "Genera el documento formal de recomendación (descargable en Word y PDF). Usalo al cerrar una recomendación o cuando el usuario lo pida. El markdown debe ser autocontenido: Contexto y requerimiento (incluye tamaño de app y criticidad), Arquitectura propuesta (tabla), Stack tecnológico, Base de datos, Seguridad (identidad, secretos, red, API Management), Costos (tabla y total), Cumplimiento del perfil, Alternativas, Supuestos, Riesgos, Requiere aprobación, Próximos pasos. No incluyas el título en el markdown.",
    "input_schema": {
      "type": "object",
      "properties": {
        "title": { "type": "string", "description": "Ej: 'Recomendación de plataforma — Moodle producción'" },
        "requester": { "type": "string", "description": "Área o persona solicitante, si se conoce." },
        "markdown": { "type": "string", "description": "Cuerpo del documento en Markdown (títulos ##, tablas, listas)." }
      },
      "required": ["title", "markdown"]
    }
  }
]
""";

    public JsonArray Definitions() => JsonNode.Parse(DefinitionsJson)!.AsArray();

    public Task<ToolResult> ExecuteAsync(string name, JsonNode input, CancellationToken ct) => name switch
    {
        "get_it_profile" => Task.FromResult(ToolResult.Ok(_profile.Root, "Perfil cargado")),
        "azure_price_lookup" => _pricing.LookupAsync(input, ct),
        "validate_proposal" => Task.FromResult(_validator.Validate(input)),
        "create_recommendation_document" => Task.FromResult(_docs.Create(input)),
        _ => Task.FromResult(ToolResult.Error($"Herramienta desconocida: {name}"))
    };
}
