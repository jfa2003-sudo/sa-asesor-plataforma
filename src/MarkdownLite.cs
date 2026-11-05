using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace InfraAdvisor;

/// <summary>Parser mínimo de Markdown (títulos, párrafos, listas, tablas, separadores, negrita/itálica/código).</summary>
public static class MarkdownLite
{
    public abstract record Block;
    public sealed record Heading(int Level, string Text) : Block;
    public sealed record Paragraph(string Text) : Block;
    public sealed record ListBlock(bool Ordered, List<string> Items) : Block;
    public sealed record Table(List<string> Header, List<List<string>> Rows) : Block;
    public sealed record Rule : Block;

    public sealed record Run(string Text, bool Bold, bool Italic, bool Code);

    public static List<Block> Parse(string md)
    {
        var lines = md.Replace("\r\n", "\n").Split('\n');
        var blocks = new List<Block>();
        var para = new List<string>();

        void FlushPara()
        {
            if (para.Count > 0) blocks.Add(new Paragraph(string.Join(" ", para).Trim()));
            para.Clear();
        }

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd();
            var t = line.Trim();

            if (t.Length == 0) { FlushPara(); continue; }

            var h = Regex.Match(t, @"^(#{1,4})\s+(.*)$");
            if (h.Success) { FlushPara(); blocks.Add(new Heading(h.Groups[1].Length, h.Groups[2].Value.Trim())); continue; }

            if (Regex.IsMatch(t, @"^(-{3,}|\*{3,}|_{3,})$")) { FlushPara(); blocks.Add(new Rule()); continue; }

            if (t.StartsWith('|'))
            {
                FlushPara();
                var rows = new List<List<string>>();
                while (i < lines.Length && lines[i].Trim().StartsWith('|'))
                {
                    var cells = lines[i].Trim().Trim('|').Split('|').Select(c => c.Trim()).ToList();
                    if (!cells.All(c => Regex.IsMatch(c, @"^:?-{2,}:?$"))) rows.Add(cells);
                    i++;
                }
                i--;
                if (rows.Count > 0) blocks.Add(new Table(rows[0], rows.Skip(1).ToList()));
                continue;
            }

            var bullet = Regex.Match(t, @"^[-*+]\s+(.*)$");
            var ordered = Regex.Match(t, @"^\d+[.)]\s+(.*)$");
            if (bullet.Success || ordered.Success)
            {
                FlushPara();
                var isOrdered = ordered.Success;
                var items = new List<string>();
                while (i < lines.Length)
                {
                    var lt = lines[i].Trim();
                    var mb = Regex.Match(lt, isOrdered ? @"^\d+[.)]\s+(.*)$" : @"^[-*+]\s+(.*)$");
                    if (mb.Success) items.Add(mb.Groups[1].Value);
                    else if (lt.Length > 0 && lines[i].StartsWith("  ") && items.Count > 0) items[^1] += " " + lt.TrimStart('-', '*', '+', ' ');
                    else break;
                    i++;
                }
                i--;
                blocks.Add(new ListBlock(isOrdered, items));
                continue;
            }

            para.Add(t);
        }
        FlushPara();
        return blocks;
    }

    public static List<Run> Inline(string text)
    {
        var runs = new List<Run>();
        var rx = new Regex(@"(\*\*[^*]+\*\*|`[^`]+`|\*[^*\s][^*]*\*|_[^_\s][^_]*_)");
        var pos = 0;
        foreach (Match m in rx.Matches(text))
        {
            if (m.Index > pos) runs.Add(new Run(text[pos..m.Index], false, false, false));
            var v = m.Value;
            if (v.StartsWith("**")) runs.Add(new Run(v[2..^2], true, false, false));
            else if (v.StartsWith('`')) runs.Add(new Run(v[1..^1], false, false, true));
            else runs.Add(new Run(v[1..^1], false, true, false));
            pos = m.Index + m.Length;
        }
        if (pos < text.Length) runs.Add(new Run(text[pos..], false, false, false));
        return runs;
    }

    public static string InlineHtml(string text)
    {
        var sb = new StringBuilder();
        foreach (var r in Inline(text))
        {
            var t = WebUtility.HtmlEncode(r.Text);
            if (r.Code) t = $"<code>{t}</code>";
            if (r.Bold) t = $"<strong>{t}</strong>";
            if (r.Italic) t = $"<em>{t}</em>";
            sb.Append(t);
        }
        return sb.ToString();
    }

    public static string ToHtml(List<Block> blocks)
    {
        var sb = new StringBuilder();
        foreach (var b in blocks)
        {
            switch (b)
            {
                case Heading h: var hl = Math.Clamp(h.Level, 2, 4); sb.Append($"<h{hl}>{InlineHtml(h.Text)}</h{hl}>"); break;
                case Paragraph p: sb.Append($"<p>{InlineHtml(p.Text)}</p>"); break;
                case Rule: sb.Append("<hr>"); break;
                case ListBlock l:
                    var tag = l.Ordered ? "ol" : "ul";
                    sb.Append($"<{tag}>");
                    foreach (var it in l.Items) sb.Append($"<li>{InlineHtml(it)}</li>");
                    sb.Append($"</{tag}>");
                    break;
                case Table t:
                    sb.Append("<table><thead><tr>");
                    foreach (var c in t.Header) sb.Append($"<th>{InlineHtml(c)}</th>");
                    sb.Append("</tr></thead><tbody>");
                    foreach (var row in t.Rows)
                    {
                        sb.Append("<tr>");
                        foreach (var c in row) sb.Append($"<td>{InlineHtml(c)}</td>");
                        sb.Append("</tr>");
                    }
                    sb.Append("</tbody></table>");
                    break;
            }
        }
        return sb.ToString();
    }
}
