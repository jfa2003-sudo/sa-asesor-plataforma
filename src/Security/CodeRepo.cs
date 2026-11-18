using System.IO.Compression;
using System.Text;

namespace InfraAdvisor.Security;

/// <summary>
/// Código fuente leído desde un zip, en memoria. Nunca se extrae a disco ni se ejecuta nada.
/// Límites contra zips maliciosos (zip bomb, rutas raras, archivos enormes).
/// </summary>
public sealed class CodeRepo
{
    public const long MaxZipBytes = 30L * 1024 * 1024;
    private const long MaxTotalTextBytes = 40L * 1024 * 1024;
    private const int MaxEntries = 20_000;
    private const int MaxFileBytes = 1024 * 1024;

    private static readonly string[] SkipDirs =
    {
        "node_modules/", ".git/", "bin/", "obj/", ".next/", "dist/", "build/", "out/", "vendor/",
        "__pycache__/", ".venv/", "venv/", "coverage/", ".idea/", ".vs/", "packages/", "target/",
    };

    private static readonly HashSet<string> TextExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".yml", ".yaml", ".md", ".txt", ".env", ".example",
        ".cs", ".csproj", ".sln", ".config", ".py", ".toml", ".ini", ".cfg", ".java", ".kt", ".gradle", ".xml",
        ".go", ".mod", ".rb", ".php", ".sql", ".sh", ".ps1", ".bicep", ".bicepparam", ".tf", ".tfvars", ".hcl",
        ".html", ".css", ".scss", ".vue", ".svelte", ".gs", ".npmrc", ".gitignore", ".dockerignore", ".properties",
        ".razor", ".cshtml", ".lock", ".conf", ".pem", ".key", ".crt",
    };

    private static readonly HashSet<string> TextNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Dockerfile", "Containerfile", "Makefile", "Procfile", "CODEOWNERS", ".env", ".npmrc", ".gitignore", ".dockerignore",
        "requirements.txt", "Gemfile", "go.mod",
    };

    public Dictionary<string, string[]> Files { get; } = new(StringComparer.Ordinal);
    public List<string> AllPaths { get; } = new();
    public List<string> BinaryOrLarge { get; } = new();
    public int SkippedEntries { get; private set; }
    public string RootPrefix { get; private set; } = "";

    public static CodeRepo Load(Stream zipStream)
    {
        var repo = new CodeRepo();
        using var zip = new ZipArchive(zipStream, ZipArchiveMode.Read, leaveOpen: false);
        if (zip.Entries.Count > MaxEntries) throw new InvalidDataException($"El zip tiene más de {MaxEntries} archivos.");

        // Si todo está bajo una sola carpeta raíz (descarga de GitHub), se quita.
        var names = zip.Entries.Where(e => !string.IsNullOrEmpty(e.Name)).Select(e => Norm(e.FullName)).ToList();
        var first = names.Select(n => n.Split('/')[0]).Distinct().ToList();
        if (first.Count == 1 && names.All(n => n.Contains('/'))) repo.RootPrefix = first[0] + "/";

        long total = 0;
        foreach (var e in zip.Entries)
        {
            if (string.IsNullOrEmpty(e.Name)) continue; // carpeta
            var full = Norm(e.FullName);
            if (full.Contains("../") || full.StartsWith('/') || full.Contains(':')) { repo.SkippedEntries++; continue; }
            var path = repo.RootPrefix.Length > 0 && full.StartsWith(repo.RootPrefix) ? full[repo.RootPrefix.Length..] : full;
            if (SkipDirs.Any(d => path.StartsWith(d) || path.Contains("/" + d))) { repo.SkippedEntries++; continue; }

            repo.AllPaths.Add(path);
            var name = Path.GetFileName(path);
            var ext = Path.GetExtension(path);
            var isText = TextNames.Contains(name) || TextExt.Contains(ext) || name.StartsWith(".env", StringComparison.OrdinalIgnoreCase);
            if (!isText || e.Length > MaxFileBytes) { repo.BinaryOrLarge.Add(path); continue; }

            total += e.Length;
            if (total > MaxTotalTextBytes) throw new InvalidDataException("El código descomprimido supera el máximo de 40 MB de texto.");

            using var s = e.Open();
            using var ms = new MemoryStream();
            // Copia acotada: no confía en el tamaño declarado en el zip.
            var buf = new byte[81920];
            int read; long acc = 0;
            while ((read = s.Read(buf, 0, buf.Length)) > 0)
            {
                acc += read;
                if (acc > MaxFileBytes) break;
                ms.Write(buf, 0, read);
            }
            if (acc > MaxFileBytes) { repo.BinaryOrLarge.Add(path); continue; }
            var bytes = ms.ToArray();
            if (bytes.AsSpan(0, Math.Min(bytes.Length, 8000)).IndexOf((byte)0) >= 0) { repo.BinaryOrLarge.Add(path); continue; }
            var text = Encoding.UTF8.GetString(bytes).Replace("\r\n", "\n");
            repo.Files[path] = text.Split('\n');
        }
        repo.AllPaths.Sort(StringComparer.Ordinal);
        return repo;
    }

    private static string Norm(string p)
    {
        var s = p.Replace('\\', '/');
        while (s.StartsWith("./")) s = s[2..];
        return s;
    }

    public bool Exists(string path) => Files.ContainsKey(path) || AllPaths.Contains(path);

    public IEnumerable<(string Path, int Line, string Text)> Grep(System.Text.RegularExpressions.Regex rx, Func<string, bool>? pathFilter = null)
    {
        foreach (var (p, lines) in Files)
        {
            if (pathFilter is not null && !pathFilter(p)) continue;
            for (var i = 0; i < lines.Length; i++)
                if (rx.IsMatch(lines[i])) yield return (p, i + 1, lines[i]);
        }
    }

    public string Tree(int max = 400)
    {
        var sb = new StringBuilder();
        foreach (var p in AllPaths.Take(max)) sb.AppendLine(p);
        if (AllPaths.Count > max) sb.AppendLine($"… y {AllPaths.Count - max} archivos más");
        return sb.ToString();
    }
}
