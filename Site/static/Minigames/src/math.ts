export class Vector2 {
    constructor(public x: number, public y: number) {}

    static fromArray(arr: number[]): Vector2 {
        return new Vector2(arr[0], arr[1]);
    }

    toArray(): number[] {
        return [this.x, this.y];
    }

    add(other: Vector2): Vector2 {
        return new Vector2(this.x + other.x, this.y + other.y);
    }

    subtract(other: Vector2): Vector2 {
        return new Vector2(this.x - other.x, this.y - other.y);
    }

    multiply(scalar: number): Vector2 {
        return new Vector2(this.x * scalar, this.y * scalar);
    }

    divide(scalar: number): Vector2 {
        if (scalar === 0) throw new Error("Cannot divide by zero");
        return new Vector2(this.x / scalar, this.y / scalar);
    }
}

export class Vector3 {
    constructor(public x: number, public y: number, public z: number) {}

    static fromArray(arr: number[]): Vector3 {
        return new Vector3(arr[0], arr[1], arr[2]);
    }

    toArray(): number[] {
        return [this.x, this.y, this.z];
    }

    add(other: Vector3): Vector3 {
        return new Vector3(this.x + other.x, this.y + other.y, this.z + other.z);
    }

    subtract(other: Vector3): Vector3 {
        return new Vector3(this.x - other.x, this.y - other.y, this.z - other.z);
    }

    multiply(scalar: number): Vector3 {
        return new Vector3(this.x * scalar, this.y * scalar, this.z * scalar);
    }

    divide(scalar: number): Vector3 {
        if (scalar === 0) throw new Error("Cannot divide by zero");
        return new Vector3(this.x / scalar, this.y / scalar, this.z / scalar);
    }
}