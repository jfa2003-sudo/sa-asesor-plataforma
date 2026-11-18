using System.Collections.Concurrent;
using System.IO.Compression;
using System.Net;
using System.Security;
using System.Text;
using System.Text.Json.Nodes;

namespace InfraAdvisor;

public sealed record RecommendationDoc(string Id, string Title, string Requester, string Markdown, DateTime CreatedUtc, string? Footer = null, string? ProfileLabel = null);

/// <summary>Genera y guarda (en memoria) los documentos de recomendación. Exporta a .docx y a vista imprimible.</summary>
public sealed class DocumentService
{
    private readonly ConcurrentDictionary<string, RecommendationDoc> _docs = new();
    private readonly ProfileStore _profile;
    private static readonly TimeSpan Ttl = TimeSpan.FromHours(24);
    private static readonly TimeZoneInfo Ba = FindBaTz();

    private readonly byte[]? _logo;

    public DocumentService(ProfileStore profile, IWebHostEnvironment env)
    {
        _profile = profile;
        // El logo vive como SVG con el PNG embebido (data URI); para Word se extraen los bytes del PNG.
        var logoPath = Path.Combine(env.WebRootPath ?? Path.Combine(env.ContentRootPath, "wwwroot"), "brand", "logo.svg");
        if (File.Exists(logoPath))
        {
            var m = System.Text.RegularExpressions.Regex.Match(File.ReadAllText(logoPath), @"data:image/png;base64,([A-Za-z0-9+/=]+)");
            if (m.Success) _logo = Convert.FromBase64String(m.Groups[1].Value);
        }
    }

    public ToolResult Create(JsonNode input)
    {
        var title = input["title"]?.GetValue<string>()?.Trim();
        var md = input["markdown"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(title) || string.IsNullOrWhiteSpace(md))
            return ToolResult.Error("Faltan title o markdown.");

        foreach (var old in _docs.Values.Where(d => DateTime.UtcNow - d.CreatedUtc > Ttl).ToList())
            _docs.TryRemove(old.Id, out _);

        var doc = new RecommendationDoc(
            Guid.NewGuid().ToString("N")[..12],
            title,
            input["requester"]?.GetValue<string>()?.Trim() ?? "",
            md,
            DateTime.UtcNow,
            input["footer"]?.GetValue<string>(),
            input["profileLabel"]?.GetValue<string>());
        _docs[doc.Id] = doc;

        var result = new JsonObject
        {
            ["documentId"] = doc.Id,
            ["title"] = doc.Title,
            ["docxUrl"] = $"/api/documents/{doc.Id}/docx",
            ["printUrl"] = $"/api/documents/{doc.Id}/print",
            ["note"] = "El usuario ya ve los botones de descarga en el chat. No repitas las URLs."
        };
        return ToolResult.Ok(result, $"Documento generado: {doc.Title}") with { Document = doc };
    }

    public RecommendationDoc? Get(string id) => _docs.TryGetValue(id, out var d) ? d : null;

    private string LocalDate(DateTime utc) => TimeZoneInfo.ConvertTimeFromUtc(utc, Ba).ToString("dd/MM/yyyy HH:mm");
    private string Org => _profile.Root["meta"]?["organization"]?.GetValue<string>() ?? "";
    private string ProfileVersion => _profile.Root["meta"]?["version"]?.GetValue<string>() ?? "";

    // ---------- Vista imprimible (PDF desde el navegador) ----------
    public string ToPrintHtml(RecommendationDoc d)
    {
        var body = MarkdownLite.ToHtml(MarkdownLite.Parse(d.Markdown));
        Func<string, string> e = s => WebUtility.HtmlEncode(s);
        return $$"""
<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{e(d.Title)}}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Source+Serif+4:wght@600;700&family=Source+Sans+3:wght@400;600&display=swap" rel="stylesheet">
<link rel="icon" href="/brand/crest.svg" type="image/svg+xml"><link rel="stylesheet" href="/doc.css">
</head><body>
<div class="toolbar"><button onclick="window.print()">Imprimir / Guardar como PDF</button><a href="/api/documents/{{d.Id}}/docx">Descargar Word</a></div>
<article class="doc">
  <header class="doc-head">
    <div class="brandline"><img src="/brand/logo.svg" alt="{{e(Org)}}"><span>Área de IT</span></div>
    <h1>{{e(d.Title)}}</h1>
    <dl>
      <div><dt>Fecha</dt><dd>{{LocalDate(d.CreatedUtc)}}</dd></div>
      {{(d.Requester.Length > 0 ? $"<div><dt>Solicitante</dt><dd>{e(d.Requester)}</dd></div>" : "")}}
      <div><dt>Perfil</dt><dd>{{e(d.ProfileLabel ?? $"Plataforma v{ProfileVersion}")}}</dd></div>
      <div><dt>Estado</dt><dd>Borrador para revisión de IT</dd></div>
    </dl>
  </header>
  <section class="doc-body">{{body}}</section>
  <footer class="doc-foot">{{e(d.Footer ?? DefaultFooter)}}</footer>
</article>
</body></html>
""";
    }

    // ---------- Word (.docx) sin dependencias externas ----------
    private const string Navy = "00478E";
    private const string DefaultFooter = "Generado por el Asesor de Plataforma. Precios de lista de Azure en USD, sin descuentos ni impuestos.";

    public byte[] ToDocx(RecommendationDoc d)
    {
        var body = new StringBuilder();
        if (_logo is not null) body.Append(LogoPara(_logo));
        else body.Append(Para(Org, style: null, color: Navy, size: 22, bold: true));
        body.Append(Para("ÁREA DE IT", style: null, color: "5E6B78", size: 16, bold: true));
        body.Append(Para(d.Title, style: "Title"));
        var meta = $"Fecha: {LocalDate(d.CreatedUtc)}" +
                   (d.Requester.Length > 0 ? $"   ·   Solicitante: {d.Requester}" : "") +
                   $"   ·   {d.ProfileLabel ?? $"Perfil v{ProfileVersion}"}   ·   Borrador para revisión de IT";
        body.Append(Para(meta, style: null, color: "5E6B78", size: 18));
        body.Append(RulePara());

        foreach (var b in MarkdownLite.Parse(d.Markdown))
        {
            switch (b)
            {
                case MarkdownLite.Heading h:
                    body.Append(RichPara(h.Text, $"Heading{Math.Clamp(h.Level - 1, 1, 3)}"));
                    break;
                case MarkdownLite.Paragraph p:
                    body.Append(RichPara(p.Text, null));
                    break;
                case MarkdownLite.Rule:
                    body.Append(RulePara());
                    break;
                case MarkdownLite.ListBlock l:
                    var n = 1;
                    foreach (var it in l.Items)
                        body.Append(RichPara(it, "ListPara", prefix: l.Ordered ? $"{n++}. " : "•  "));
                    break;
                case MarkdownLite.Table t:
                    body.Append(TableXml(t));
                    body.Append("<w:p/>");
                    break;
            }
        }
        body.Append(Para(d.Footer ?? DefaultFooter,
            style: null, color: "5E6B78", size: 16, italic: true));

        var document = $"""
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
<w:body>{body}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr></w:body>
</w:document>
""";

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
        {
            Add(zip, "[Content_Types].xml", """
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="png" ContentType="image/png"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>
""");
            Add(zip, "_rels/.rels", """
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
""");
            Add(zip, "word/_rels/document.xml.rels", """
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rIdLogo" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/logo.png"/>
</Relationships>
""");
            Add(zip, "word/styles.xml", StylesXml());
            Add(zip, "word/document.xml", document);
            var logoEntry = zip.CreateEntry("word/media/logo.png", CompressionLevel.NoCompression);
            using (var ls = logoEntry.Open()) ls.Write(_logo ?? Array.Empty<byte>());
        }
        return ms.ToArray();
    }

    private static void Add(ZipArchive zip, string path, string content)
    {
        var entry = zip.CreateEntry(path, CompressionLevel.Optimal);
        using var w = new StreamWriter(entry.Open(), new UTF8Encoding(false));
        w.Write(content.TrimStart());
    }

    private static string LogoPara(byte[] png)
    {
        // Tamaño real del PNG (bytes 16-23 del header IHDR), alto fijo 0,45"
        int w = (png[16] << 24) | (png[17] << 16) | (png[18] << 8) | png[19];
        int h = (png[20] << 24) | (png[21] << 16) | (png[22] << 8) | png[23];
        long cy = (long)(0.45 * 914400);
        long cx = h > 0 ? cy * w / h : cy * 6;
        return $"""<w:p><w:pPr><w:spacing w:after="60"/></w:pPr><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{cx}" cy="{cy}"/><wp:docPr id="1" name="Logo"/><wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:nvPicPr><pic:cNvPr id="0" name="logo.png"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="rIdLogo"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>""";
    }

    private static string X(string s) => SecurityElement.Escape(s) ?? "";

    private static string Para(string text, string? style, string? color = null, int? size = null, bool bold = false, bool italic = false)
    {
        var ppr = style is null ? "" : $"<w:pPr><w:pStyle w:val=\"{style}\"/></w:pPr>";
        var rpr = new StringBuilder();
        if (bold) rpr.Append("<w:b/>");
        if (italic) rpr.Append("<w:i/>");
        if (color is not null) rpr.Append($"<w:color w:val=\"{color}\"/>");
        if (size is not null) rpr.Append($"<w:sz w:val=\"{size}\"/>");
        var r = rpr.Length > 0 ? $"<w:rPr>{rpr}</w:rPr>" : "";
        return $"<w:p>{ppr}<w:r>{r}<w:t xml:space=\"preserve\">{X(text)}</w:t></w:r></w:p>";
    }

    private static string Runs(string text, bool forceBold = false)
    {
        var sb = new StringBuilder();
        foreach (var r in MarkdownLite.Inline(text))
        {
            var rpr = new StringBuilder();
            if (r.Bold || forceBold) rpr.Append("<w:b/>");
            if (r.Italic) rpr.Append("<w:i/>");
            if (r.Code) rpr.Append("<w:rFonts w:ascii=\"Consolas\" w:hAnsi=\"Consolas\"/><w:sz w:val=\"18\"/>");
            sb.Append($"<w:r>{(rpr.Length > 0 ? $"<w:rPr>{rpr}</w:rPr>" : "")}<w:t xml:space=\"preserve\">{X(r.Text)}</w:t></w:r>");
        }
        return sb.ToString();
    }

    private static string RichPara(string text, string? style, string prefix = "")
    {
        var ppr = style is null ? "" : $"<w:pPr><w:pStyle w:val=\"{style}\"/></w:pPr>";
        var pre = prefix.Length > 0 ? $"<w:r><w:t xml:space=\"preserve\">{X(prefix)}</w:t></w:r>" : "";
        return $"<w:p>{ppr}{pre}{Runs(text)}</w:p>";
    }

    private static string RulePara() =>
        $"<w:p><w:pPr><w:pBdr><w:bottom w:val=\"single\" w:sz=\"8\" w:space=\"1\" w:color=\"{Navy}\"/></w:pBdr></w:pPr></w:p>";

    private static string TableXml(MarkdownLite.Table t)
    {
        var cols = Math.Max(t.Header.Count, t.Rows.Count == 0 ? 0 : t.Rows.Max(r => r.Count));
        var sb = new StringBuilder();
        sb.Append("<w:tbl><w:tblPr><w:tblStyle w:val=\"TableGrid\"/><w:tblW w:w=\"5000\" w:type=\"pct\"/>");
        sb.Append("<w:tblBorders>");
        foreach (var side in new[] { "top", "left", "bottom", "right", "insideH", "insideV" })
            sb.Append($"<w:{side} w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"C9D3DE\"/>");
        sb.Append("</w:tblBorders><w:tblCellMar><w:left w:w=\"80\" w:type=\"dxa\"/><w:right w:w=\"80\" w:type=\"dxa\"/></w:tblCellMar></w:tblPr>");
        sb.Append("<w:tblGrid>");
        for (var i = 0; i < cols; i++) sb.Append("<w:gridCol/>");
        sb.Append("</w:tblGrid>");

        string Row(List<string> cells, bool header)
        {
            var r = new StringBuilder("<w:tr>");
            if (header) r.Append("<w:trPr><w:tblHeader/></w:trPr>");
            for (var i = 0; i < cols; i++)
            {
                var txt = i < cells.Count ? cells[i] : "";
                var shade = header ? $"<w:shd w:val=\"clear\" w:color=\"auto\" w:fill=\"{Navy}\"/>" : "";
                var runs = header
                    ? $"<w:r><w:rPr><w:b/><w:color w:val=\"FFFFFF\"/></w:rPr><w:t xml:space=\"preserve\">{X(StripMd(txt))}</w:t></w:r>"
                    : Runs(txt);
                r.Append($"<w:tc><w:tcPr>{shade}</w:tcPr><w:p><w:pPr><w:spacing w:before=\"40\" w:after=\"40\"/></w:pPr>{runs}</w:p></w:tc>");
            }
            return r.Append("</w:tr>").ToString();
        }

        sb.Append(Row(t.Header, true));
        foreach (var row in t.Rows) sb.Append(Row(row, false));
        sb.Append("</w:tbl>");
        return sb.ToString();
    }

    private static string StripMd(string s) => string.Concat(MarkdownLite.Inline(s).Select(r => r.Text));

    private static string StylesXml() => $"""
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults>
  <w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="es-AR"/></w:rPr></w:rPrDefault>
  <w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault>
</w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="120" w:after="60"/></w:pPr><w:rPr><w:rFonts w:ascii="Georgia" w:hAnsi="Georgia"/><w:b/><w:color w:val="{Navy}"/><w:sz w:val="40"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="280" w:after="100"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:rFonts w:ascii="Georgia" w:hAnsi="Georgia"/><w:b/><w:color w:val="{Navy}"/><w:sz w:val="30"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:rFonts w:ascii="Georgia" w:hAnsi="Georgia"/><w:b/><w:color w:val="{Navy}"/><w:sz w:val="26"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="200" w:after="60"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:color w:val="{Navy}"/><w:sz w:val="23"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListPara"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="60"/><w:ind w:left="567" w:hanging="283"/></w:pPr></w:style>
<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:rPr><w:sz w:val="19"/></w:rPr></w:style>
</w:styles>
""";

    private static TimeZoneInfo FindBaTz()
    {
        try { return TimeZoneInfo.FindSystemTimeZoneById("America/Argentina/Buenos_Aires"); }
        catch { return TimeZoneInfo.CreateCustomTimeZone("ART", TimeSpan.FromHours(-3), "ART", "ART"); }
    }
}
