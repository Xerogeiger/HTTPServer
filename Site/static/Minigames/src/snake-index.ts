// Simple Snake Game
import { CookieManager } from './cookie-manager.js';

interface Point { x: number; y: number; }

class SnakeGame {
  private canvas: HTMLCanvasElement;
  private scoreboard: HTMLElement;
  private ctx: CanvasRenderingContext2D;
  private gridSize = 20; // number of cells horizontally
  private cellSize = 20; // pixels per cell
  private snake: Point[] = [];
  private direction: Point = { x: 1, y: 0 };
  private food: Point = { x: 5, y: 5 };
  private gameInterval: number | null = null;
  private score = 0;
  private scoreEl: HTMLElement | null;
  private highScoreEl: HTMLElement | null;
  private highScoreCookie = new CookieManager('snakeHighScore');

  constructor(canvasId: string) {
    const canvas = document.getElementById(canvasId) as HTMLCanvasElement | null;
    if (!canvas) throw new Error('Canvas not found');
    this.canvas = canvas;

    let scoreboard = document.getElementById('scoreboard') as HTMLElement | null;
    if (!scoreboard) throw new Error('Scoreboard element not found');
    this.scoreboard = scoreboard;

    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('Canvas context missing');
    this.ctx = ctx;
    this.scoreEl = document.getElementById('score');
    this.highScoreEl = document.getElementById('highScore');
    this.reset();
    document.addEventListener('keydown', (e) => this.handleKey(e));
  }

  private reset() {
    this.snake = [ { x: 3, y: 3 }, { x: 2, y: 3 }, { x: 1, y: 3 } ];
    this.direction = { x: 1, y: 0 };
    this.placeFood();
    this.score = 0;
    if (this.scoreEl) this.scoreEl.textContent = `Score: ${this.score}`;
  }

  public start() {
    if (this.gameInterval !== null) return;
    this.gameInterval = window.setInterval(() => this.update(), 150);
    this.scoreboard.classList.add('hidden');
  }

  public restart() {
    if (this.gameInterval !== null) {
      clearInterval(this.gameInterval);
      this.gameInterval = null;
    }
    this.reset();
    this.start();
  }

  private handleKey(e: KeyboardEvent) {
    switch (e.code) {
      case 'ArrowUp': if (this.direction.y === 0) this.direction = { x: 0, y: -1 }; break;
      case 'ArrowDown': if (this.direction.y === 0) this.direction = { x: 0, y: 1 }; break;
      case 'ArrowLeft': if (this.direction.x === 0) this.direction = { x: -1, y: 0 }; break;
      case 'ArrowRight': if (this.direction.x === 0) this.direction = { x: 1, y: 0 }; break;
    }
  }

  private placeFood() {
    //Check if the whole grid is filled
    if (this.snake.length >= this.gridSize * this.gridSize) {
      this.endGame();
      return;
    }

    const max = this.gridSize - 1;
    this.food = {
      x: Math.floor(Math.random() * (max + 1)),
      y: Math.floor(Math.random() * (max + 1)),
    };

    // Ensure food does not spawn on the snake
    while (this.snake.some(segment => segment.x === this.food.x && segment.y === this.food.y)) {
      this.food.x = Math.floor(Math.random() * (max + 1));
      this.food.y = Math.floor(Math.random() * (max + 1));
    }
  }

  private update() {
    const head = { x: this.snake[0].x + this.direction.x, y: this.snake[0].y + this.direction.y };

    // Check collisions with walls
    if (head.x < 0 || head.x >= this.gridSize || head.y < 0 || head.y >= this.gridSize) {
      this.endGame();
      return;
    }

    // Check collisions with self
    if (this.snake.some(segment => segment.x === head.x && segment.y === head.y)) {
      this.endGame();
      return;
    }

    this.snake.unshift(head);

    // Check food
    if (head.x === this.food.x && head.y === this.food.y) {
      this.score++;
      if (this.scoreEl) this.scoreEl.textContent = `Score: ${this.score}`;
      this.placeFood();
    } else {
      this.snake.pop();
    }

    this.draw();
  }

  private draw() {
    this.ctx.fillStyle = '#222';
    this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);

    // draw food
    this.ctx.fillStyle = 'red';
    this.ctx.fillRect(this.food.x * this.cellSize, this.food.y * this.cellSize, this.cellSize, this.cellSize);

    // draw snake
    this.ctx.fillStyle = 'lime';
    for (const s of this.snake) {
      this.ctx.fillRect(s.x * this.cellSize, s.y * this.cellSize, this.cellSize, this.cellSize);
    }
  }

  private endGame() {
    if (this.gameInterval !== null) {
      clearInterval(this.gameInterval);
      this.gameInterval = null;
    }
    const high = parseInt(this.highScoreCookie.get() ?? '0', 10);
    if (this.score > high) this.highScoreCookie.set(String(this.score), { days: 30 });
    if (this.highScoreEl) this.highScoreEl.textContent = `High Score: ${this.highScoreCookie.get()}`;
    this.scoreboard.classList.remove('hidden');
  }
}

function startGame() {
  const game = new SnakeGame('gameCanvas');
  game.start();
  (window as any).snakeGame = game;
}

window.startGame = startGame;
