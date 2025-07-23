import {parseInlines, parseLatexMath} from './inlineParsers.js';
import { parseBlocks } from './blockParsers.js';

export function renderBlock(block) {
    const L = block.lines;
    switch (block.type) {
        case 'heading':
            return renderHeading(L);
        case 'code':
            return renderCode(L);

        case 'ul': {
            // 1) Is this a task‐list?
            const isTaskList = L.some(line =>
                /^\s*(?:[-+*])\s*\[[ xX]\]\s+/.test(line)
            );

            // 2) Map each line to <li>…</li>
            const items = L.map(line => {
                const taskMatch = line.match(
                    /^\s*(?:[-+*])\s*\[([ xX])\]\s+(.*)$/
                );
                if (taskMatch) {
                    const checked = taskMatch[1].toLowerCase() === 'x';
                    return `<li class="task-list-item">
                    <input type="checkbox" disabled${checked ? ' checked' : ''}/>
                    ${parseInlines(taskMatch[2])}
                  </li>`;
                }
                // normal bullet
                const text = line.replace(/^\s*[-+*]\s+/, '');
                return `<li>${parseInlines(text)}</li>`;
            }).join('');

            return `<ul${isTaskList ? ' class="task-list"' : ''}>${items}</ul>`;
        }

        case 'ol': {
            const isTaskList = L.some(line =>
                /^\s*\d+\.\s*\[[ xX]\]\s+/.test(line)
            );

            const items = L.map(line => {
                const taskMatch = line.match(
                    /^\s*\d+\.\s*\[([ xX])\]\s+(.*)$/
                );
                if (taskMatch) {
                    const checked = taskMatch[1].toLowerCase() === 'x';
                    return `<li class="task-list-item">
                    <input type="checkbox" disabled${checked ? ' checked' : ''}/>
                    ${parseInlines(taskMatch[2])}
                  </li>`;
                }
                // normal numbered
                const text = line.replace(/^\s*\d+\.\s+/, '');
                return `<li>${parseInlines(text)}</li>`;
            }).join('');

            return `<ol${isTaskList ? ' class="task-list"' : ''}>${items}</ol>`;
        }

        case 'blockquote':
            return renderBlockquote(L);
        case 'table':
            return renderTable(L);
        case 'hr':
            return renderHr(L);
        case 'mathblock': {
            const expr = L.join('\n');
            return `<div class="math">${parseLatexMath(expr)}</div>`;
        }
        case 'deflist': {
            let html = '<dl>';
            for (let i = 0; i < L.length; ) {
                // Term line
                const term = L[i++].trim();
                html += `<dt>${parseInlines(term)}</dt>`;

                // One or more definition lines
                while (i < L.length && /^[ \t]*:\s+/.test(L[i])) {
                    const def = L[i++].replace(/^[ \t]*:\s+/, '');
                    html += `<dd>${parseInlines(def)}</dd>`;
                }
            }
            html += '</dl>';
            return html;
        }
        default:
            return renderParagraph(L);
    }
}


export function renderBlocks(blocks) {
    return blocks.map(renderBlock).join('');
}

const OL_ITEM = /^\s*(\d+)[.)]\s+(.*)$/;

export function renderHeading(lines) {
    const text = lines[0].trim();
    const level = text.match(/^#+/)[0].length;
    const content = parseInlines(text.replace(/^#+\s*/, ''));
    return `<h${level}>${content}</h${level}>`;
}

export function renderCode(lines) {
    // ```lang on first line, code in between, closing ``` last line
    const info = lines[0].slice(3).trim();
    const codeText = lines.slice(1, -1).join('\n');
    const escaped = codeText
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    return `<pre><code${info ? ` class="language-${info}"` : ''}>${escaped}</code></pre>`;
}

export function renderParagraph(lines) {
    const text = lines.join(' ').trim();
    return `<p>${parseInlines(text)}</p>`;
}

export function renderHr(lines) {
    return '<hr />';
}

export function renderTable(lines) {
    const [headerLine, sepLine, ...body] = lines;
    const headers = headerLine.replace(/^\||\|$/g, '').split('|').map(h => h.trim());
    const aligns = sepLine
        .replace(/^\||\|$/g, '')
        .split('|')
        .map(cell => {
            if (/^:-+:$/.test(cell.trim())) return 'center';
            if (/^:-+/.test(cell.trim())) return 'left';
            if (/^-+:$/.test(cell.trim())) return 'right';
            return '';
        });
    let html = '<table><thead><tr>';
    headers.forEach((h, i) => {
        html += `<th${aligns[i] ? ` align="${aligns[i]}"` : ''}>${parseInlines(h)}</th>`;
    });
    html += '</tr></thead><tbody>';

    body.forEach(row => {
        const cells = row.replace(/^\||\|$/g, '').split('|').map(c => c.trim());
        html += '<tr>';
        cells.forEach((c, i) => {
            html += `<td${aligns[i] ? ` align="${aligns[i]}"` : ''}>${parseInlines(c)}</td>`;
        });
        html += '</tr>';
    });

    html += '</tbody></table>';
    return html;
}

export function renderUl(lines) {
    let html = '<ul>';
    lines.forEach(line => {
        const content = line.replace(/^\s*[-+*]\s+/, '').trim();
        html += `<li>${parseInlines(content)}</li>`;
    });
    html += '</ul>';
    return html;
}

export function renderOl(lines) {
    let start = 1;
    const indentStack = [-1];
    let html = '';

    lines.forEach(line => {
        const match = line.match(OL_ITEM);
        if (!match) return;
        const [ , num, rest ] = match;
        const indent = line.search(/\d/);
        if (html === '') start = parseInt(num, 10);

        if (indent > indentStack[indentStack.length - 1]) {
            html += `<ol${html === '' && start !== 1 ? ` start="${start}"` : ''}>`;
            indentStack.push(indent);
        } else if (indent < indentStack[indentStack.length - 1]) {
            while (indent < indentStack[indentStack.length - 1]) {
                html += '</li></ol>';
                indentStack.pop();
            }
            html += '</li>';
        } else if (html !== '') {
            html += '</li>';
        }

        html += `<li>${parseInlines(rest.trim())}`;
    });

    while (indentStack.length > 0) {
        html += '</li></ol>';
        indentStack.pop();
    }

    return html;
}

export function renderBlockquote(lines) {
    // Strip leading '>' and one optional space
    const stripped = lines.map(line => line.replace(/^\s*> ?/, ''));
    // Re-parse inner content
    const innerBlocks = parseBlocks(stripped);
    // Render inner blocks
    const innerHtml = innerBlocks.map(renderBlock).join('');
    return `<blockquote>${innerHtml}</blockquote>`;
}
