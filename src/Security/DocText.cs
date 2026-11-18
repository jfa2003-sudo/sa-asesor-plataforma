using System.IO.Compression;
using System.Text;
using System.Xml;

namespace InfraAdvisor.Security;

/// <summary>Texto plano del documento de arquitectura (.docx, .md, .txt o .json).</summary>
public static class DocText
{
    public const int MaxChars = 80_000;

    public static string Extract(Stream s, string fileName)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        string text = ext switch
        {
            ".docx" => FromDocx(s),
            ".md" or ".txt" or ".json" => new StreamReader(s, Encoding.UTF8).ReadToEnd(),
            _ => throw new InvalidDataException("El documento de arquitectura tiene que ser .docx, .md, .txt o .json."),
        };
        return text.Length > MaxChars ? text[..MaxChars] + "\n…(documento truncado)" : text;
    }

    private static string FromDocx(Stream s)
    {
        using var zip = new ZipArchive(s, ZipArchiveMode.Read);
        var entry = zip.GetEntry("word/document.xml") ?? throw new InvalidDataException("El .docx no tiene word/document.xml.");
        if (entry.Length > 20 * 1024 * 1024) throw new InvalidDataException("El documento es demasiado grande.");
        using var es = entry.Open();
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        using var xr = XmlReader.Create(es, settings);
        var sb = new StringBuilder();
        var line = new StringBuilder();
        var inCell = false;
        var inText = false;
        while (xr.Read())
        {
            if (xr.NodeType == XmlNodeType.Element)
            {
                switch (xr.LocalName)
                {
                    case "t": inText = !xr.IsEmptyElement; break;
                    case "tab": line.Append('\t'); break;
                    case "br": line.Append('\n'); break;
                    case "tc": inCell = true; break;
                }
            }
            else if ((xr.NodeType == XmlNodeType.Text || xr.NodeType == XmlNodeType.SignificantWhitespace || xr.NodeType == XmlNodeType.Whitespace) && inText)
            {
                line.Append(xr.Value);
            }
            else if (xr.NodeType == XmlNodeType.EndElement)
            {
                switch (xr.LocalName)
                {
                    case "t": inText = false; break;
                    case "p":
                        if (inCell) line.Append(' ');
                        else { sb.AppendLine(line.ToString().TrimEnd()); line.Clear(); }
                        break;
                    case "tc": line.Append(" | "); inCell = false; break;
                    case "tr": sb.AppendLine("| " + line.ToString().TrimEnd()); line.Clear(); break;
                }
            }
        }
        if (line.Length > 0) sb.AppendLine(line.ToString());
        return sb.ToString();
    }
}
