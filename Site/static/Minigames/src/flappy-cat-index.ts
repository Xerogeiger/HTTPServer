class Box {
    public x: number;
    public y: number;
    public width: number;
    public height: number;

    constructor(x: number, y: number, width: number, height: number) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
    }
}

function isOverlapping(box1: Box, box2: Box): boolean {
    return !(
        box1.x + box1.width < box2.x ||
        box1.x > box2.x + box2.width ||
        box1.y + box1.height < box2.y ||
        box1.y > box2.y + box2.height
    );
}

function isPointInBox(point: { x: number, y: number }, box: Box): boolean {
    return (
        point.x >= box.x &&
        point.x <= box.x + box.width &&
        point.y >= box.y &&
        point.y <= box.y + box.height
    );
}

function drawRepeatingImage(ctx: CanvasRenderingContext2D, image: HTMLImageElement, x: number, y: number, width: number, height: number) {
    const pattern = ctx.createPattern(image, 'repeat');
    if (!pattern) return;
    const scale = width / image.width;
    pattern.setTransform(new DOMMatrix().translate(x, y).scale(scale));
    if (pattern) {
        ctx.fillStyle = pattern;
        ctx.fillRect(x, y, width, height);
    }
}

class FlappyCatGame {
    private catBox: Box;
    private walls: Box[];
    private canvas: HTMLCanvasElement;
    private catImage: HTMLImageElement;
    private brickImage: HTMLImageElement;
    private backgroundImage: HTMLImageElement;
    private velocityY: number = 0;
    private gravity: number = 350;
    private flapStrength: number = -200;
    private wallSpeed: number = 100;
    private score: number = 0;
    private scoreEl: HTMLElement | null;
    private animationId: number | undefined;
    private lastUpdateTime: number = 0;
    private flapNoise: HTMLAudioElement;
    private scoreSound: HTMLAudioElement;
    private flapNoisePlaying: boolean = false;

    constructor() {
        this.canvas = document.getElementById('game-canvas') as HTMLCanvasElement;
        this.catBox = new Box(30, this.canvas.height/2 - 25, 66.59356725, 50); // Assuming cat is 50x50 pixels
        this.walls = [];
        this.flapNoise = new Audio('./sounds/wing-flap.mp3'); // Path to the flap sound
        this.flapNoise.volume = 0.3; // Set volume for the flap sound
        this.scoreSound = new Audio('./sounds/win-sound.wav'); // Path to the score sound
        this.scoreSound.volume = 0.2; // Set volume for the score sound

        this.catImage = new Image();
        this.catImage.src = 'img/flappy-cat.png'; // Path to the cat image
        this.catImage.onload = () => {
            this.drawGame(); // Draw the game once the cat image is loaded
        };

        this.brickImage = new Image();
        this.brickImage.src = 'img/bricks.png'; // Path to the wall image
        this.brickImage.onload = () => {
            this.drawGame(); // Draw the game once the wall image is loaded
        };

        this.backgroundImage = new Image();
        this.backgroundImage.src = 'img/flappycat-background.png'; // Path to the background image
        this.backgroundImage.onload = () => {
            this.drawGame(); // Draw the game once the background image is loaded
        };

        this.scoreEl = document.getElementById('score-display');
        this.createWalls(0, 3, 150);

        // Input handlers for flapping
        this.canvas.addEventListener('mousedown', () => this.flap());
        document.addEventListener('keydown', (e) => {
            console.log(`Key pressed: ${e.code}`);
            if (e.code === 'Space') {
                e.preventDefault();
                this.flap();
            }
        });
    }

    public createWalls(y: number, count: number, gap: number) {
        const wallWidth = 50; // Width of each wall
        const lastY = this.canvas.height/2;
        for (let i = 0; i < count; i++) {
            const x = 200 + i * (wallWidth + gap); // Calculate x position based on index and gap
            const height = Math.random() * (this.canvas.height - 200) + 50; // Random height for the wall
            this.walls.push(new Box(x, y, wallWidth, height));

            // Add a second wall for the gap
            const secondWallY = y + height + gap; // Position the second wall below the gap
            const secondWallHeight = this.canvas.height - secondWallY; // Remaining height for the second wall
            this.walls.push(new Box(x, secondWallY, wallWidth, secondWallHeight));
        }
    }

    private loop(currentTime?: number) {
        this.animationId = requestAnimationFrame((time) => this.loop(time));
        const now = currentTime ?? performance.now();
        const deltaTime = (now - this.lastUpdateTime) / 1000.0;
        this.lastUpdateTime = now;
        this.updateGame(deltaTime);
    }

    private flap() {
        this.velocityY = this.flapStrength;
        // Play flap sound
        if(this.flapNoisePlaying) return; // Prevent multiple plays

        this.flapNoisePlaying = true;
        this.flapNoise.currentTime = 0; // Reset sound to start
        this.flapNoise.play().catch(error => {
            console.error('Error playing flap sound:', error);
        }).then(() => {
            console.log('Flap sound played successfully');
            this.flapNoisePlaying = false; // Reset playing state after sound is played
        });
    }

    public updateGame(deltaTime: number) {
        console.log(`Delta time: ${deltaTime.toFixed(2)} seconds`);
        // Apply gravity to the cat
        this.velocityY += this.gravity * deltaTime;
        this.catBox.y += this.velocityY * deltaTime;

        // Prevent the cat from leaving the canvas vertically
        if (this.catBox.y < 0) {
            this.catBox.y = 0;
            this.velocityY = 0;
        }
        if (this.catBox.y + this.catBox.height > this.canvas.height) {
            this.catBox.y = this.canvas.height - this.catBox.height;
            this.velocityY = 0;
        }

        // Move walls to the left and recycle them when off screen
        for (const wall of this.walls) {
            wall.x -= this.wallSpeed * deltaTime;
        }

        if (this.walls.length) {
            // Destructure the first two walls as a pair
            const [wall1, wall2] = this.walls;

            if (wall1.x + wall1.width < 0) {
                // 1) Remove them from the front
                const moved1 = this.walls.shift()!;
                const moved2 = this.walls.shift()!;

                // 2) Compute the new X based on the current last wall
                const last = this.walls[this.walls.length - 1];
                const newX = last.x + last.width + 120;

                // 3) Reposition both walls to that X
                moved1.x = newX;
                moved2.x = newX;

                // 4) Push them back *in order* so they stay paired
                this.walls.push(moved1, moved2);

                // 5) Update score display
                this.score++;
                if (this.scoreSound) {
                    this.scoreSound.currentTime = 0; // Reset sound to start
                    this.scoreSound.play().catch(error => {
                        console.error('Error playing score sound:', error);
                    });
                }
                if (this.scoreEl) {
                    this.scoreEl.textContent = `Score: ${this.score}`;
                }
            }
        }

        if (this.checkCollision()) {
            this.gameOver();
        }
        this.drawGame();
    }

    public gameOver() {
        if (typeof this.animationId === "number") {
            cancelAnimationFrame(this.animationId);
        }
        // Show game over message
        const gameOverMessage = document.getElementById('game-over-overlay');
        if (gameOverMessage) {
            gameOverMessage.style.display = 'block';
        }

        // Show the score
        const finalScore = document.getElementById('final-score');
        if (finalScore) {
            finalScore.textContent = `Your score: ${this.score}`;
        }

        // Hide the game container
        const gameContainer = document.getElementById('game-container');
        if (gameContainer) {
            gameContainer.style.display = 'none';
        }

        // Reset the game state
        this.resetGame();
    }

    public resetGame() {
        this.catBox.y = this.canvas.height / 2 - 25;
        this.velocityY = 0;
        this.walls = [];
        this.score = 0;
        if (this.scoreEl) {
            this.scoreEl.textContent = `Score: ${this.score}`;
        }
        this.createWalls(0, 3, 150);
        this.drawGame();
    }

    public startGame() {
        const instructions = document.getElementById('instructions-box');
        if (instructions) {
            instructions.style.display = 'none';
        }

        // Hide game over message
        const gameOverMessage = document.getElementById('game-over-overlay') as HTMLElement;
        gameOverMessage.style.display = 'none';

        // @ts-ignore
        document.getElementById('game-container').style.display = 'block';

        // Reset game state and start the loop
        this.resetGame();
        this.lastUpdateTime = performance.now();
        this.loop(this.lastUpdateTime);
    }

    public drawGame() {
        const ctx = this.canvas.getContext('2d');
        if (!ctx) return;

        // Clear the canvas
        ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

        // Draw the background
        ctx.drawImage(this.backgroundImage, 0, 0, this.canvas.width, this.canvas.height);

        // Draw the cat
        // Rotate tee cat image based on velocity
        ctx.save();
        ctx.translate(this.catBox.x + this.catBox.width / 2, this.catBox.y + this.catBox.height / 2);
        const maxDegrees = 45;
        const factor = 0.01;
        let angleDeg = maxDegrees * (1 - Math.exp(-factor * Math.abs(this.velocityY)));
        let angleRad = angleDeg * Math.sign(this.velocityY) * (Math.PI / 180);
        ctx.rotate(angleRad);
        ctx.drawImage(this.catImage, -this.catBox.width / 2, -this.catBox.height / 2, this.catBox.width, this.catBox.height);
        ctx.restore();

        // Draw the walls
        // Fill with repeating wall image
        for (let wall of this.walls) {
            drawRepeatingImage(ctx, this.brickImage, wall.x, wall.y, wall.width, wall.height);
        }
    }

    public checkCollision(): boolean {
        for (let wall of this.walls) {
            if (isOverlapping(this.catBox, wall)) {
                return true; // Collision detected
            }
        }
        return false; // No collision
    }

    public checkCatPosition(point: { x: number, y: number }): boolean {
        return isPointInBox(point, this.catBox);
    }
}

let game: FlappyCatGame;

function startGame() {
    if(!game) {
        game = new FlappyCatGame();
    } else {
        game.resetGame(); // Reset the game state if it already exists
    }

    const instructions = document.getElementById('instructions-box');
    if (instructions) {
        instructions.style.display = 'none';
    }
    // @ts-ignore
    document.getElementById('game-container').style.display = 'block';
    game.startGame();
}

function restartGame() {
    game.resetGame();
    game.startGame();
}