using System.Text.Json.Nodes;

namespace InfraAdvisor;

/// <summary>Perfil de plataforma definido por IT (JSON). Se carga al iniciar.</summary>
public sealed class ProfileStore
{
    public JsonObject Root { get; }
    public string Raw { get; }

    private ProfileStore(string raw)
    {
        Raw = raw;
        Root = JsonNode.Parse(raw)?.AsObject() ?? throw new InvalidOperationException("Perfil vacío");
    }

    public static ProfileStore Load(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException($"No se encontró el perfil de IT en {path}");
        return new ProfileStore(File.ReadAllText(path));
    }

    public string[] AllowedRegions =>
        Root["regions"]?["allowed"]?.AsArray().Select(n => n!.GetValue<string>()).ToArray() ?? Array.Empty<string>();

    public string PrimaryRegion => Root["regions"]?["primary"]?.GetValue<string>() ?? AllowedRegions.FirstOrDefault() ?? "";
    public string? DrRegion => Root["regions"]?["dr"]?.GetValue<string>();
    public double HoursPerMonth => Root["hoursPerMonth"]?.GetValue<double>() ?? 730;

    public JsonObject? Environment(string name) => Root["environments"]?[name] as JsonObject;
    public JsonObject? Criticality(string name) => Root["criticality"]?[name] as JsonObject;

    public string[] RequiredTags =>
        Root["tagging"]?["required"]?.AsArray().Select(n => n!.GetValue<string>()).ToArray() ?? Array.Empty<string>();

    public string[] EnvironmentNames => (Root["environments"] as JsonObject)?.Select(p => p.Key).ToArray() ?? Array.Empty<string>();
    public string[] CriticalityNames => (Root["criticality"] as JsonObject)?.Select(p => p.Key).ToArray() ?? Array.Empty<string>();
}
