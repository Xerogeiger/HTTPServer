// BitFlipper Puzzle Game

/**
 * BitFlipPuzzle:
 *   - gridSize: N
 *   - board: boolean[][]  (false = 0, true = 1)
 *   - moveCount: number
 *
 * On “New Game”:
 *   1. Read N from <select>
 *   2. Initialize board = all zeros (or all false)
 *   3. Perform K random “legal” flips starting from solved state to guarantee solvable.
 *   4. Render the grid.
 *
 * On cell-click at (r, c):
 *   1. Flip (r,c) and its up/down/left/right neighbors if in bounds.
 *   2. Increment moveCount
 *   3. Re-render affected cells
 *   4. Check if solved (all same); if yes, show overlay.
 */

type CellState = 0 | 1;

class BitFlipPuzzle {
    private gridSize: number;
    private board: CellState[][];
    private moveCount: number;

    private gridEl: HTMLDivElement;
    private moveCountEl: HTMLSpanElement;
    private winOverlayEl: HTMLDivElement;
    private finalMovesEl: HTMLParagraphElement;
    private sizeSelectEl: HTMLSelectElement;
    private newGameBtn: HTMLButtonElement;
    private playAgainBtn: HTMLButtonElement;

    constructor() {
        // Cache DOM references
        this.gridEl = document.getElementById('grid') as HTMLDivElement;
        this.moveCountEl = document.getElementById('moveCount') as HTMLSpanElement;
        this.winOverlayEl = document.getElementById('winOverlay') as HTMLDivElement;
        this.finalMovesEl = document.getElementById('finalMoves') as HTMLParagraphElement;
        this.sizeSelectEl = document.getElementById('sizeSelect') as HTMLSelectElement;
        this.newGameBtn = document.getElementById('newGameBtn') as HTMLButtonElement;
        this.playAgainBtn = document.getElementById('playAgainBtn') as HTMLButtonElement;

        // Bind event handlers
        this.newGameBtn.addEventListener('click', () => this.startNewGame());
        this.playAgainBtn.addEventListener('click', () => this.startNewGame());

        this.gridSize = 0;
        this.board = [];
        this.moveCount = 0;

        // On load, start with default size
        this.startNewGame();
    }

    public getGridState(): string {
        return this.board.map(row => row.join('')).join('\n');
    }

    public setGridState(state: string): void {
        const rows = state.split('\n');
        this.gridSize = rows.length;
        this.board = rows.map(row => row.split('').map(Number) as CellState[]);
        this.moveCount = 0; // Reset move count
        this.updateMoveCountDisplay();
        this.renderGrid(); // Re-render grid based on new state

        // Hide win overlay if visible
        this.winOverlayEl.classList.add('hidden');
    }

    private startNewGame(): void {
        // 1. Read gridSize from <select>
        this.gridSize = parseInt(this.sizeSelectEl.value, 10);
        this.gridEl.style.width = `${(this.gridSize * (50 + 25))}px`; // 50px per cell and 25px for the pathway

        // 2. Initialize board as all zeros
        this.board = Array.from({ length: this.gridSize }, () =>
            Array<CellState>(this.gridSize).fill(0)
        );

        // 3. Reset moveCount
        this.moveCount = 0;
        this.updateMoveCountDisplay();

        // 4. Perform random flips to generate a solvable puzzle
        this.randomizeBoard( this.gridSize * this.gridSize * 3 );

        // 5. Render grid structure & contents
        this.renderGrid();

        // Hide win overlay if visible
        this.winOverlayEl.classList.add('hidden');
    }

    /**
     * randomizeBoard(k): starting from all-zeros, apply k random flips.
     * This guarantees solvable since reversing the same k flips solves it.
     */
    private randomizeBoard(k: number): void {
        for (let i = 0; i < k; i++) {
            const r = this.randomInt(0, this.gridSize - 1);
            const c = this.randomInt(0, this.gridSize - 1);
            this.flipAt(r, c, false);
            // We pass false to not count as a user move
        }
    }

    /**
     *  Animate a little rectangle traveling from cell (r,c) to cell (nr,nc).
     *  We:
     *   1) find each cell’s DOM element, get their boundingClientRect centers
     *   2) append a \<div class="signal-rect"\> at the source center
     *   3) force a reflow, then set its CSS transform so it moves to dest center
     *   4) listen for transitionend, then remove the element
     */
    private travelSignal(r: number, c: number, nr: number, nc: number): void {
        // 1) Find the source and dest cell elements
        const srcSelector = `.cell[data-row="${r}"][data-col="${c}"]`;
        const dstSelector = `.cell[data-row="${nr}"][data-col="${nc}"]`;
        const srcCell = this.gridEl.querySelector(srcSelector) as HTMLElement;
        const dstCell = this.gridEl.querySelector(dstSelector) as HTMLElement;
        if (!srcCell || !dstCell) return; // out of bounds or not yet rendered

        // 2) Get bounding rects so we can compute each center (relative to #grid)
        const gridRect = this.gridEl.getBoundingClientRect();
        const srcRect  = srcCell.getBoundingClientRect();
        const dstRect  = dstCell.getBoundingClientRect();

        // compute center-of-cell coordinates relative to the top-left of #grid:
        const srcCenterX = srcRect.left + srcRect.width / 2  - gridRect.left;
        const srcCenterY = srcRect.top  + srcRect.height / 2 - gridRect.top;
        const dstCenterX = dstRect.left + dstRect.width / 2  - gridRect.left;
        const dstCenterY = dstRect.top  + dstRect.height / 2 - gridRect.top;

        // 3) Create an absolutely positioned <div class="signal-rect"> at (srcCenterX, srcCenterY)
        const pulse = document.createElement('div');
        pulse.classList.add('signal-rect');
        // position its center at srcCenterX, srcCenterY:
        pulse.style.left = `${srcCenterX}px`;
        pulse.style.top  = `${srcCenterY}px`;

        // Append it into #grid
        this.gridEl.appendChild(pulse);

        // 4) Force a reflow so that the browser “registers” the initial position
        //    (otherwise, if we immediately set transform, it might not animate)
        //    Just reading offsetWidth is enough to force reflow:
        void pulse.offsetWidth;

        // 5) Now change its transform so it goes to (dstCenterX, dstCenterY) over 200ms
        //    Because we already set `transform: translate(-50%, -50%)` in CSS,
        //    we can add an extra translate() to move from src to dst:
        const dx = dstCenterX - srcCenterX;
        const dy = dstCenterY - srcCenterY;

        pulse.style.transform = `translate(-50%, -50%) translate(${dx}px, ${dy}px)`;

        // 6) When the transition finishes, remove the pulse from the DOM
        pulse.addEventListener(
            'transitionend',
            () => {
                pulse.remove();
            },
            { once: true }
        );
    }


    /**
     *  Override your existing flipAt(...) so that before toggling bits, we send a “travel”
     *  from (r,c) to each neighbor (nr,nc). If you’d also like to flip the center last,
     *  you can chain a travel from (r,c)→(r,c) to show a self‐pulse, but typically you
     *  just want to go from the clicked cell to its up/down/left/right neighbors.
     */
    private flipAt(r: number, c: number, countMove: boolean = true): void {
        if(countMove) { //Play bloop sound
            const sound = new Audio('sounds/bloop-sound.wav');
            sound.play().catch(err => {
                console.error('Error playing sound:', err);
            });
        }

        // 1) For each orthogonal neighbor, trigger a rectangle‐travel from center→neighbor
        const neighborOffsets: Array<[number, number]> = [
            [-1,  0],
            [ 1,  0],
            [ 0, -1],
            [ 0,  1],
        ];
        neighborOffsets.forEach(([dr, dc], idx) => {
            const nr = r + dr;
            const nc = c + dc;
            if (
                nr < 0 || nr >= this.gridSize
                || nc < 0 || nc >= this.gridSize
            ) {
                return; // out of bounds
            }

            setTimeout(() => {
                this.travelSignal(r, c, nr, nc);
            }, 100);
        });

        // 2) Now actually toggle the bits (center + neighbors) in the board[][]
        const deltas = [
            [  0,  0 ],
            [ -1,  0 ],
            [  1,  0 ],
            [  0, -1 ],
            [  0,  1 ],
        ];
        for (const [dr, dc] of deltas) {
            const nr = r + dr;
            const nc = c + dc;
            if (
                nr < 0 || nr >= this.gridSize
                || nc < 0 || nc >= this.gridSize
            ) continue;
            this.board[nr][nc] = this.board[nr][nc] === 0 ? 1 : 0;
        }

        // 3) If this is a real user move (not part of randomization), update move count & UI
        if (countMove) {
            this.moveCount++;
            this.updateMoveCountDisplay();
            this.updateRow(r);
            this.updateRow(r - 1);
            this.updateRow(r + 1);
            this.updateCell(r, c);
            this.checkWin();
        }
    }

    /** Update the “Moves: X” display */
    private updateMoveCountDisplay(): void {
        this.moveCountEl.textContent = `Moves: ${this.moveCount}`;
    }

    /** Returns a random integer between min and max (inclusive) */
    private randomInt(min: number, max: number): number {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    /** Build grid markup & attach click listeners */
    private renderGrid(): void {
        // Clear previous content
        this.gridEl.innerHTML = '';

        // Set CSS grid-template based on size
        this.gridEl.style.gridTemplateColumns = `repeat(${this.gridSize * 2 - 1}, 1fr)`;
        this.gridEl.style.gridTemplateRows = `repeat(${this.gridSize * 2 - 1}, 1fr)`;

        // Create cells
        for (let r = 0; r < this.gridSize; r++) {
            for (let c = 0; c < this.gridSize; c++) {
                if(c != 0) {
                    // Add a pathway cell between columns
                    const pathEl = document.createElement('div');
                    pathEl.classList.add('pathway');
                    pathEl.classList.add('horizontal');
                    this.gridEl.appendChild(pathEl);
                }

                const cellEl = document.createElement('div');
                cellEl.classList.add('cell');
                cellEl.dataset.row = r.toString();
                cellEl.dataset.col = c.toString();
                this.updateCellAppearance(cellEl, this.board[r][c]);

                // Click handler
                cellEl.addEventListener('click', () => {
                    this.flipAt(r, c, true);
                    this.refreshAllCells();
                });

                this.gridEl.appendChild(cellEl);
            }

            if(r != this.gridSize - 1) {
                for (let c = 0; c < this.gridSize; c++) {
                    if(c != 0) {
                        // Add a blank cell
                        const pathEl = document.createElement('div');
                        this.gridEl.appendChild(pathEl);
                    }
                    // Add a pathway cell between rows
                    const pathEl = document.createElement('div');
                    pathEl.classList.add('pathway');
                    pathEl.classList.add('vertical');
                    this.gridEl.appendChild(pathEl);
                }
            }
        }
    }

    /** Update a single cell’s color/text based on state */
    private updateCellAppearance(cellEl: HTMLDivElement, state: CellState): void {
        cellEl.classList.remove('zero', 'one');
        if (state === 0) {
            cellEl.classList.add('zero');
            cellEl.textContent = '0';
        } else {
            cellEl.classList.add('one');
            cellEl.textContent = '1';
        }
    }

    /** After flipping, update just the affected cells in row r (and its neighbors) */
    private updateRow(r: number): void {
        if (r < 0 || r >= this.gridSize) return;
        for (let c = 0; c < this.gridSize; c++) {
            this.updateCell(r, c);
        }
    }

    /** Update a single cell in the DOM at (r, c) */
    private updateCell(r: number, c: number): void {
        // Query the corresponding .cell by data-row, data-col
        const selector = `.cell[data-row="${r}"][data-col="${c}"]`;
        const cellEl = this.gridEl.querySelector(selector) as HTMLDivElement;
        if (cellEl) {
            this.updateCellAppearance(cellEl, this.board[r][c]);
        }
    }

    /**
     * If you want a simpler approach: after each flip, just re-render all cells:
     *   this.refreshAllCells();
     * That loops over all r,c and updates each .cell.
     */
    private refreshAllCells(): void {
        for (let r = 0; r < this.gridSize; r++) {
            for (let c = 0; c < this.gridSize; c++) {
                this.updateCell(r, c);
            }
        }
    }

    /** Check if board is solved (all zeros or all ones) */
    private checkWin(): void {
        let sum = 0;
        for (let r = 0; r < this.gridSize; r++) {
            for (let c = 0; c < this.gridSize; c++) {
                sum += this.board[r][c];
            }
        }
        if (sum === 0 || sum === this.gridSize * this.gridSize) {
            // Solved
            this.showWinOverlay();
        }
    }

    /** Display overlay with final move count */
    private showWinOverlay(): void {
        this.finalMovesEl.textContent = `You used ${this.moveCount} moves.`;
        this.winOverlayEl.classList.remove('hidden');

        //Play win sound
        const winSound = new Audio('sounds/win-sound.wav');
        winSound.play().catch(err => {
            console.error('Error playing win sound:', err);
        });
    }
}


// Initialize once DOM is loaded
window.addEventListener('DOMContentLoaded', () => {
    new BitFlipPuzzle();
});
