import { Vector2 } from './math.js';
import {CookieManager} from "./cookie-manager.js";

class Car {
    private position: Vector2;
    private speed: number;
    private carImage: HTMLImageElement | null = null;
    public width: number = 50;
    public height: number = 75;

    constructor(position : Vector2, size: Vector2 , speed: number, imageSrc: string) {
        this.position = position;
        this.speed = speed;
        this.width = size.x;
        this.height = size.y;
        this.carImage = new Image();
        this.carImage.src = imageSrc;
    }

    public move(direction: Vector2): void {
        this.position = this.position.add(direction.multiply(this.speed));
    }

    public getPosition(): Vector2 {
        return this.position;
    }

    public setPosition(x: number, y: number): void {
        this.position = new Vector2(x, y);
    }

    public getSpeed(): number {
        return this.speed;
    }

    public setSpeed(speed: number): void {
        this.speed = speed;
    }

    public draw(ctx: CanvasRenderingContext2D, rotation: number): void {
        if (!this.carImage) {
            throw new Error("Car image not loaded");
        }

        if (!ctx) {
            throw new Error("Canvas context is not available");
        }

        let drawCar = (image: HTMLImageElement) => {
            ctx.save();
            ctx.translate(this.position.x + (this.width/2), this.position.y);
            ctx.rotate(rotation * Math.PI / 180);
            ctx.drawImage(image, -this.width/2, -this.height/2, this.width, this.height);
            ctx.restore();
        }

        if (!this.carImage.complete) {
            this.carImage.onload = () => {
                drawCar(this.carImage as HTMLImageElement);
            };
            return;
        } else {
            drawCar(this.carImage as HTMLImageElement);
        }
    }
}

class StreetRacer {
    private cars: Car[] = [];
    private pathOffsets: number[] = [];
    private playerCar: Car;
    private playerLane: number = 1;
    private canvas: HTMLCanvasElement;
    private scoreElement: HTMLElement | null = null;
    private finalScoreElement: HTMLElement | null = null;
    private highScoreElement: HTMLElement | null = null;
    private score: number = 0;
    private carOffsetX = 0;
    private lastUpdateTime = 0;
    private animationId: number | null = null;
    private highScoreCookie: CookieManager;
    private touchStartX: number | null = null;
    private carSize: Vector2;
    private carCrashSound: HTMLAudioElement;
    private carStartSound: HTMLAudioElement;

    constructor(canvasId: string) {
        this.canvas = document.getElementById(canvasId) as HTMLCanvasElement;
        if (!this.canvas) {
            throw new Error(`Canvas with id ${canvasId} not found`);
        }

        this.scoreElement = document.getElementById('score');
        if (!this.scoreElement) {
            throw new Error("Score element not found");
        }

        this.finalScoreElement = document.getElementById('finalScore');
        if (!this.finalScoreElement) {
            throw new Error("Final score element not found");
        }

        this.highScoreElement = document.getElementById('highScore');
        if (!this.highScoreElement) {
            throw new Error("High score element not found");
        }

        // Initialize car crash sound
        this.carCrashSound = new Audio('./sounds/car-crash.mp3');
        this.carCrashSound.preload = 'auto';
        this.carCrashSound.volume = 0.1; // Set volume to a reasonable level

        // Initialize car start sound
        this.carStartSound = new Audio('./sounds/car-start.mp3');
        this.carStartSound.preload = 'auto';
        this.carStartSound.volume = 0.1; // Set volume to a reasonable level

        this.carSize = new Vector2(this.canvas.width * 0.1, this.canvas.width * 0.15);
        this.carOffsetX = (this.canvas.width / 3) - (this.carSize.x/3); // Center the car horizontally
        this.pathOffsets = [
            this.carOffsetX * 0.5,
            this.carOffsetX * 2 - (this.carOffsetX * 0.5),
            this.carOffsetX * 3 - (this.carOffsetX * 0.5) // Adjusted to fit three lanes
        ];
        this.playerCar = new Car(new Vector2(this.pathOffsets[this.playerLane], this.canvas.height - 100), this.carSize, 5, './img/RedCar.png');

        // Listen for player input
        document.addEventListener('keydown', (e) => {
            if (e.code === 'ArrowLeft') {
                this.changeLane(-1);
            }
            if (e.code === 'ArrowRight') {
                this.changeLane(1);
            }
        });

        // Make it so that when the player clicks on one side or the other of the screen, the car will change lanes
        this.canvas.addEventListener('click', (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const x = e.clientX - rect.left;
            if (x < this.canvas.width / 2) {
                this.changeLane(-1); // Left side
            } else {
                this.changeLane(1); // Right side
            }
        });

        // Support swipe gestures on touch devices
        this.canvas.addEventListener('touchstart', (e) => {
            if (e.touches && e.touches.length > 0) {
                this.touchStartX = e.touches[0].clientX;
            }
        }, { passive: true });

        this.canvas.addEventListener('touchend', (e) => {
            if (this.touchStartX === null || !e.changedTouches || e.changedTouches.length === 0) {
                this.touchStartX = null;
                return;
            }
            const deltaX = e.changedTouches[0].clientX - this.touchStartX;
            if (Math.abs(deltaX) > 30) {
                this.changeLane(deltaX > 0 ? 1 : -1);
            }
            this.touchStartX = null;
        }, { passive: true });

        // Initialize high score cookie
        this.highScoreCookie = new CookieManager('highScore');

        this.initCars();
        this.drawGame();
    }

    private initCars(): void {
        this.spawnCar();
        this.spawnCar();
        this.lastUpdateTime = Date.now();
    }

    private spawnCar(): void {
        const carImages = [
            './img/BlueCar.png',
            './img/GreenCar.png',
            './img/YellowCar.png'
        ];
        let lane = Math.floor(Math.random() * this.pathOffsets.length);

        // Ensure the car is in a different lange than the other cars
        for (const car of this.cars) {
            if (car.getPosition().x === this.pathOffsets[lane]) {
                lane = (lane + 1) % this.pathOffsets.length; // Change lane if occupied
            }
        }

        const x = this.pathOffsets[lane];
        const y = -75;
        const speed = Math.random() * 6 + 10;
        const image = carImages[Math.floor(Math.random() * carImages.length)];
        this.cars.push(new Car(new Vector2(x, y), this.carSize, speed, image));
    }

    private changeLane(direction: number): void {
        const newLane = this.playerLane + direction;
        if (newLane < 0 || newLane >= this.pathOffsets.length) {
            return;
        }
        this.playerLane = newLane;
        this.playerCar.setPosition(this.pathOffsets[this.playerLane], this.playerCar.getPosition().y);
    }

    public start(): void {
        //Reset game state if already running
        if (this.animationId !== null) {
            this.stop();
        }
        // Reset player car position
        this.playerCar.setPosition(this.pathOffsets[this.playerLane], this.canvas.height - 100);
        // Reset cars array
        this.cars = [];
        // Reset score and UI elements
        if (this.scoreElement) {
            this.scoreElement.textContent = `Score: 0`;
        }


        if (this.animationId === null) {
            this.lastUpdateTime = Date.now();
            this.score = 0;
            this.carStartSound.currentTime = 1; // Reset sound to start
            this.carStartSound.play().catch((error: any) => {
                console.error("Error playing start sound:", error);
            });
            //Fade sound out
            this.carStartSound.volume = 0.1; // Set initial volume
            let fadeOutVolume = 0.1;

            // Start fading out the sound after a delay
            setTimeout(() => {
                const fadeOutInterval = setInterval(() => {
                    if (fadeOutVolume > 0) {
                        fadeOutVolume -= 0.01; // Decrease volume
                        this.carStartSound.volume = fadeOutVolume;
                    } else {
                        clearInterval(fadeOutInterval);
                    }
                }, 100); // Adjust the interval timing as needed
            }, 1000); // Start fading out after 1 second

            //Stop car sound after a few seconds
            setTimeout(() => {
                this.carStartSound.pause();
            }, 3000);
            if(this.scoreElement) {
                this.scoreElement.textContent = `Score: ${this.score}`;
            }
            this.animationId = requestAnimationFrame(() => this.gameLoop());
        }
    }

    public stop(): void {
        if (this.animationId !== null) {
            cancelAnimationFrame(this.animationId);
            this.animationId = null;
        }
    }

    private gameLoop(): void {
        this.updateGame();
        this.drawGame();
        if (this.animationId !== null) {
            this.animationId = requestAnimationFrame(() => this.gameLoop());
        }
    }

    private updateGame(): void {
        const now = Date.now();
        const deltaTime = (now - this.lastUpdateTime) / 1000;
        this.lastUpdateTime = now;

        this.cars.forEach((car) => {
            const direction = new Vector2(0, car.getSpeed() * deltaTime);
            car.move(direction);
        });

        // Remove cars that have gone off screen
        for (let i = this.cars.length - 1; i >= 0; i--) {
            const car = this.cars[i];
            if (car.getPosition().y - (car.height/2) > this.canvas.height) {
                this.cars.splice(i, 1);
                this.score++;
                if (this.scoreElement) {
                    this.scoreElement.textContent = `Score: ${this.score}`;
                }
            }
        }

        // Spawn new cars to maintain two on screen
        while (this.cars.length < 2) {
            this.spawnCar();
        }

        // Check for collisions
        for (const car of this.cars) {
            if (this.isColliding(this.playerCar, car)) {
                console.log("Collision detected!");
                // Check for high score
                const highScore = parseInt(this.highScoreCookie.get() || '0', 10);
                if (this.score > highScore) {
                    this.highScoreCookie.set(this.score.toString(), { days: 30 });
                }
                if (this.highScoreElement) {
                    this.highScoreElement.textContent = `High Score: ${this.highScoreCookie.get()}`;
                }
                if (this.finalScoreElement) {
                    this.finalScoreElement.textContent = `Final Score: ${this.score}`;
                }
                this.gameOver();
                return;
            }
        }
    }

    private drawGame(): void {
        const ctx = this.canvas.getContext('2d');
        if (!ctx) {
            throw new Error("Failed to get canvas context");
        }

        ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

        // Draw player car
        this.playerCar.draw(ctx, 0);

        // Draw other cars
        for (const car of this.cars) {
            car.draw(ctx, 180);
        }
    }

    private isColliding(a: Car, b: Car): boolean {
        const posA = a.getPosition();
        const posB = b.getPosition();
        return (
            posA.x < posB.x + b.width &&
            posA.x + a.width > posB.x &&
            posA.y < posB.y + b.height &&
            posA.y + a.height > posB.y
        );
    }

    private gameOver(): void {
        this.stop();
        const overlay = document.getElementById('game-over-overlay');
        if (overlay) {
            overlay.style.display = 'flex';
        }

        // Play crash sound
        this.carCrashSound.currentTime = 0; // Reset sound to start
        this.carCrashSound.play().catch((error: any) => {
            console.error("Error playing crash sound:", error);
        });

        if(this.scoreElement)
            this.scoreElement.textContent = `Final Score: ${this.score}`;
    }
}

let game: StreetRacer | null = null;

function startGame() {
    if (!game) {
        game = new StreetRacer('gameCanvas');
    }
    game.start();
}

function stopGame() {
    game?.stop();
}

function restartGame() {
    stopGame();
    const overlay = document.getElementById('game-over-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
    if(!game) {
        game = new StreetRacer('gameCanvas');
    }
    game.start();
}

(window as any).startGame = startGame;
(window as any).stopGame = stopGame;
(window as any).restartGame = restartGame;
