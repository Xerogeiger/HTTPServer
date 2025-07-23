class PolygonMatchGame {
    private shapes = [
        'hexagon',
        'square',
        'triangle',
        'diamond',
        'pentagon',
        'octagon',
        'trapezoid',
        'parallelogram',
        'star',
        'cross',
        'chevron',
        'arrow',
        'heart',
        'pill',
        'circle',
    ];
    private cards: HTMLDivElement[] = [];
    private firstCard: HTMLDivElement | null = null;
    private secondCard: HTMLDivElement | null = null;
    private lock = false;
    private moveCount = 0;

    private gridEl: HTMLDivElement;
    private moveCountEl: HTMLSpanElement;
    private newGameBtn: HTMLButtonElement;
    private playAgainBtn: HTMLButtonElement;
    private winOverlayEl: HTMLDivElement;
    private bloopSound: HTMLAudioElement;

    constructor() {
        this.gridEl = document.getElementById('game-grid') as HTMLDivElement;
        this.moveCountEl = document.getElementById('moveCount') as HTMLSpanElement;
        this.newGameBtn = document.getElementById('newGameBtn') as HTMLButtonElement;
        this.playAgainBtn = document.getElementById('playAgainBtn') as HTMLButtonElement;
        this.winOverlayEl = document.getElementById('winOverlay') as HTMLDivElement;

        this.bloopSound = new Audio('./sounds/bloop-sound.wav');

        this.newGameBtn.addEventListener('click', () => this.startNewGame());
        this.playAgainBtn.addEventListener('click', () => this.startNewGame());

        this.startNewGame();
    }

    private startNewGame() {
        this.cards = [];
        this.gridEl.innerHTML = '';
        this.moveCount = 0;
        this.updateMoveCount();
        this.winOverlayEl.classList.add('hidden');

        const pairShapes = [...this.shapes, ...this.shapes];
        this.shuffle(pairShapes);

        pairShapes.forEach(shape => {
            const card = document.createElement('div');
            card.classList.add('card');
            card.dataset.shape = shape;
            card.innerHTML = `<div class="shape ${shape}"></div>`;
            card.addEventListener('click', () => this.onCardClicked(card));
            this.gridEl.appendChild(card);
            this.cards.push(card);
        });
    }

    private shuffle(array: string[]) {
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
        }
    }

    private onCardClicked(card: HTMLDivElement) {
        if (this.lock || card === this.firstCard || card.classList.contains('matched')) return;
        card.classList.add('revealed');
        this.bloopSound.currentTime = 0; // Reset sound to start
        this.bloopSound.play().catch(error => {
            console.error('Error playing sound:', error);
        });
        if (!this.firstCard) {
            this.firstCard = card;
            return;
        }
        this.secondCard = card;
        this.lock = true;
        this.moveCount++;
        this.updateMoveCount();

        if (this.firstCard.dataset.shape === this.secondCard.dataset.shape) {
            this.firstCard.classList.add('matched');
            this.secondCard.classList.add('matched');
            this.resetSelection();
            if (this.cards.every(c => c.classList.contains('matched'))) {
                this.winOverlayEl.classList.remove('hidden');
            }
        } else {
            setTimeout(() => {
                this.firstCard?.classList.remove('revealed');
                this.secondCard?.classList.remove('revealed');
                this.resetSelection();
            }, 1000);
        }
    }

    private resetSelection() {
        this.firstCard = null;
        this.secondCard = null;
        this.lock = false;
    }

    private updateMoveCount() {
        this.moveCountEl.textContent = `Moves: ${this.moveCount}`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new PolygonMatchGame();
});
