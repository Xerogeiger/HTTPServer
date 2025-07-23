import { parseBlocks } from './blockParsers.js';
import {renderBlock, renderBlocks} from './renderers.js';
import {parseInlines} from "./inlineParsers.js";

let _footnotes = {};  // holds id → raw markdown text
export let _linkDefs = {};  // holds id → { url, title }

export function renderMarkdown(md) {
    _linkDefs = {};
    const bodyLines = [];
    for (const line of md.split('\n')) {
        const m = line.match(/^\[([^\]]+)\]:\s*(\S+)(?:\s+"([^"]+)")?$/);
        if (m) {
            // m[1] = id, m[2] = url, m[3] = optional title
            _linkDefs[m[1]] = { url: m[2], title: m[3] || '' };
        } else {
            bodyLines.push(line);
        }
    }

    // 1) extract footnote definitions
    _footnotes = {};
    const lines = [];
    md.split('\n').forEach(line => {
        const m = line.match(/^\[\^(.+?)\]:\s*(.+)$/);
        if (m) {
            _footnotes[m[1]] = m[2];
        } else {
            lines.push(line);
        }
    });

    // 2) render body
    const bodyHtml = parseBlocks(lines).map(renderBlock).join('');

    // 3) if footnotes exist, render them
    let fnHtml = '';
    const ids = Object.keys(_footnotes);
    if (ids.length) {
        fnHtml = [
            '<section class="footnotes">',
            '<hr/>',
            '<ol>',
            ...ids.map(id => {
                // parse inline Markdown in the definition
                const def = parseInlines(_footnotes[id]);
                return `<li id="fn:${id}">${def} <a href="#fnref:${id}" class="footnote-backref">↩︎</a></li>`;
            }),
            '</ol>',
            '</section>'
        ].join('\n');
    }

    return bodyHtml + fnHtml;
}