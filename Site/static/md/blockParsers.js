export function parseBlocks(lines) {
    const blocks = [];
    let buffer = [];

    function flush() {
        if (!buffer.length) return;
        blocks.push({ type: detectType(buffer), lines: buffer });
        buffer = [];
    }

    const LIST_ITEM = /^\s*(?:[-+*]|\d+\.)\s+/;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // ——— Definition list: term + one or more ": definition" lines ———
        if (
            // current line is non-blank and not starting with list/quote/code/table markup
            line.trim() &&
            !/^\s*(?:[-+*]|\d+\.|>|\||```|##?)/.test(line) &&
            i + 1 < lines.length &&
            /^[ \t]*:\s+/.test(lines[i + 1])
        ) {
            flush();
            const defLines = [ line ];
            // consume all the following ": ..." lines
            i++;
            while (i < lines.length && /^[ \t]*:\s+/.test(lines[i])) {
                defLines.push(lines[i++]);
            }
            blocks.push({ type: 'deflist', lines: defLines });
            i--;  // step back one, since outer for() will i++ again
            continue;
        }

        // ——— One-line bracket math ———
        let m;
        if ((m = line.match(/^\s*\\\[(.+?)\\\]\s*$/))) {
            flush();
            blocks.push({ type: 'mathblock', lines: [ m[1] ] });
            continue;
        }

        // ——— Multi-line bracket math ———
        if (/^\\\[\s*$/.test(line)) {
            flush();
            const inner = [];
            i++;
            while (i < lines.length && !/^\s*\\\]\s*$/.test(lines[i])) {
                inner.push(lines[i++]);
            }
            blocks.push({ type: 'mathblock', lines: inner });
            continue;
        }

        // ——— $$…$$ math fence ———
        if (/^\$\$\s*$/.test(line)) {
            flush();
            const inner = [];
            i++;
            while (i < lines.length && !/^\$\$\s*$/.test(lines[i])) {
                inner.push(lines[i++]);
            }
            blocks.push({ type: 'mathblock', lines: inner });
            continue;
        }

        // ——— Fenced code block ———
        if (/^```/.test(line)) {
            flush();
            const codeLines = [ line ];
            i++;
            while (i < lines.length && !/^```/.test(lines[i])) {
                codeLines.push(lines[i++]);
            }
            if (i < lines.length) codeLines.push(lines[i]);
            blocks.push({ type: 'code', lines: codeLines });
            continue;
        }

        // ——— Table ———
        if (
            /^\|.*\|/.test(line) &&
            i + 1 < lines.length &&
            /^\s*\|?[-:]+[-| :]*\|/.test(lines[i + 1])
        ) {
            flush();
            const tableLines = [ line ];
            i++;
            tableLines.push(lines[i]);
            while (i + 1 < lines.length && /^\|.*\|/.test(lines[i + 1])) {
                i++;
                tableLines.push(lines[i]);
            }
            blocks.push({ type: 'table', lines: tableLines });
            continue;
        }

        // ——— List ———
        if (LIST_ITEM.test(line)) {
            if (!buffer.length || !LIST_ITEM.test(buffer[0])) flush();
            buffer.push(line);
        }
        // ——— Blockquote ———
        else if (/^\s*>/.test(line)) {
            if (!buffer.length || buffer[0].trim().charAt(0) !== '>') flush();
            buffer.push(line);
        }
        // ——— Anything else ———
        else {
            flush();
            buffer.push(line);
        }
    }

    flush();
    return blocks;
}

export function detectType(blockLines) {
    const first = blockLines[0].trim();

    if (blockLines.length > 1 &&
        !/^\s*(?:[-+*]|\d+\.|>|\||```|#+|-{3,})/.test(blockLines[0]) &&
        /^[ \t]*:\s+/.test(blockLines[1])) {
        return 'deflist';
    }
    if (/^#{1,6}\s/.test(first)) return 'heading';
    if (/^```/.test(first)) return 'code';
    if (/^\s*[-+*]\s+/.test(first)) return 'ul';
    if (/^\s*\d+\.\s+/.test(first)) return 'ol';
    if (/^\s*>/.test(first)) return 'blockquote';
    if (/^\|.*\|/.test(first) && blockLines[1] && /^\s*\|?[-:]+[-| :]*\|/.test(blockLines[1])) return 'table';
    if (/^---+$/.test(first)) return 'hr';
    return 'paragraph';
}
