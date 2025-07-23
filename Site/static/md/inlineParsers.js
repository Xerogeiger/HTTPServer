import {_linkDefs} from "./core.js";

export function parseLatexMath(expr) {
    // 0) Relational operators
    expr = expr
        .replace(/\\geq/g, '≥')
        .replace(/\\leq/g, '≤')
        .replace(/\\neq/g, '≠')
        .replace(/\\times/g, '×');

    // 1) Integrals
    expr = expr.replace(
        /\\int\s*(?:_\{([\s\S]+?)\}|_([A-Za-z0-9]+))?\s*(?:\^\{([\s\S]+?)\}|\^([A-Za-z0-9]+))?/g,
        (_, sub1, sub2, sup1, sup2) => {
            const lower = sub1 || sub2;
            const upper = sup1 || sup2;
            let html = '<span class="int">';
            if (upper) html += `<span class="int-sup">${upper}</span>`;
            html += '<span class="int-sym">∫</span>';
            if (lower) html += `<span class="int-sub">${lower}</span>`;
            html += '</span>';
            return html;
        }
    );

    // 2) Summations
    expr = expr.replace(
        /\\sum\s*(?:_\{([\s\S]+?)\}|_([A-Za-z0-9]+))?\s*(?:\^\{([\s\S]+?)\}|\^([A-Za-z0-9]+))?/g,
        (_, sub1, sub2, sup1, sup2) => {
            const lower = sub1 || sub2;
            const upper = sup1 || sup2;
            let html = '<span class="sum">';
            if (upper) html += `<span class="sum-sup">${upper}</span>`;
            html += '<span class="sum-sym">∑</span>';
            if (lower) html += `<span class="sum-sub">${lower}</span>`;
            html += '</span>';
            return html;
        }
    );

    // 3) Fractions: \frac{numerator}{denominator}
    expr = expr.replace(
        /\\frac\s*\{([\s\S]+?)\}\s*\{([\s\S]+?)\}/g,
        '<span class="frac"><span class="num">$1</span><span class="den">$2</span></span>'
    );

    // 4) Square roots: \sqrt{…}
    expr = expr.replace(
        /\\sqrt\s*\{([\s\S]+?)\}/g,
        '<span class="sqrt">√($1)</span>'
    );

    // 5) Plus/minus: \pm
    expr = expr.replace(/\\pm/g, '±');

    // 6) Remaining subscripts & superscripts (single-char or braced)
    expr = expr
        .replace(/_\{([\s\S]+?)\}/g, '<sub>$1</sub>')
        .replace(/_([A-Za-z0-9]+)/g, '<sub>$1</sub>')
        .replace(/\^\{([\s\S]+?)\}/g, '<sup>$1</sup>')
        .replace(/\^([A-Za-z0-9]+)/g, '<sup>$1</sup>');

    return expr;
}

export function parseInlines(text) {
    // 0) footnote references: [^id]
    text = text.replace(/\[\^([^\]]+?)\]/g, (_, id) => {
        return `<sup id="fnref:${id}"><a href="#fn:${id}">[${id}]</a></sup>`;
    });

    // a) Image reference: ![alt][id]
    text = text.replace(/!\[([^\]]+)\]\[([^\]]+)\]/g, (_, alt, id) => {
        const def = _linkDefs[id];
        if (!def) return `![${alt}][${id}]`;  // leave untouched if missing
        const title = def.title ? ` title="${def.title}"` : '';
        return `<img src="${def.url}" alt="${alt}"${title}>`;
    });

    // b) Link reference: [text][id]
    text = text.replace(/\[([^\]]+)\]\[([^\]]+)\]/g, (_, txt, id) => {
        const def = _linkDefs[id];
        if (!def) return `[${txt}][${id}]`;
        const title = def.title ? ` title="${def.title}"` : '';
        return `<a href="${def.url}"${title}>${txt}</a>`;
    });

    // 1) Extract inline HTML
    const htmlFragments = [];
    const placeholder = (_, idx) => `\0HTML${idx}\0`;
    text = text.replace(/<[^>]+>/g, match => {
        const i = htmlFragments.push(match) - 1;
        return placeholder(null, i);
    });

    // 2) Escape everything else
    const escapeHtml = str =>
        str.replace(/&/g,'&amp;')
            .replace(/</g,'&lt;')
            .replace(/>/g,'&gt;');

    // 3) Markdown transforms (bold, links, math, etc.)
    let out = escapeHtml(text)
        // 5) Strikethrough: ~~text~~
        .replace(/~~(.+?)~~/g, '<del>$1</del>')
        .replace(/__([^_]+)__/g, '<sub>$1</sub>')
        // superscript: ^text^
        .replace(/\^([^\^]+)\^/g, '<sup>$1</sup>')
        // inline math / display math would go here if you have those rules…
        .replace(/\$\$(.+?)\$\$/gs, (m, expr) => `<div class="math">${parseLatexMath(expr)}</div>`)
        .replace(/\$(.+?)\$/g,      (m, expr) => `<span class="math">${parseLatexMath(expr)}</span>`)
        .replace(/\*\*(.+?)\*\*/g,  '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g,      '<em>$1</em>')
        .replace(/`([^`]+)`/g,      '<code>$1</code>')
        .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')
        .replace(/\^([^\^]+)\^/g,   '<sup>$1</sup>')
        .replace(/~([^~]+)~/g,      '<sub>$1</sub>');

    // 4) Restore inline HTML fragments
    out = out.replace(/\0HTML(\d+)\0/g, (_, idx) => htmlFragments[idx]);

    return out;
}
