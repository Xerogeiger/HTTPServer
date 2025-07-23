export interface CookieOptions {
    /** Number of days before the cookie expires. */
    days?: number;
    /** Path attribute for the cookie. Defaults to '/'. */
    path?: string;
}

/**
 * Simple utility for storing and retrieving a single cookie value.
 * The cookie is identified by a name provided at construction time.
 */
export class CookieManager {
    constructor(private name: string) {}

    /**
     * Set the cookie to the provided value.
     * @param value - Value to store.
     * @param options - Optional cookie attributes like `days` and `path`.
     */
    public set(value: string, options: CookieOptions = {}): void {
        const path = options.path ?? '/';
        let expires = '';
        if (options.days !== undefined) {
            const date = new Date();
            date.setTime(date.getTime() + options.days * 86400000);
            expires = '; expires=' + date.toUTCString();
        }
        document.cookie = `${encodeURIComponent(this.name)}=${encodeURIComponent(value)}${expires}; path=${path}`;
    }

    /** Retrieve the current cookie value or null if not present. */
    public get(): string | null {
        const nameEq = encodeURIComponent(this.name) + '=';
        const parts = document.cookie.split(';');
        for (let c of parts) {
            c = c.trim();
            if (c.startsWith(nameEq)) {
                return decodeURIComponent(c.substring(nameEq.length));
            }
        }
        return null;
    }

    /** Remove the cookie by setting an expired date. */
    public delete(path: string = '/'): void {
        document.cookie = `${encodeURIComponent(this.name)}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${path}`;
    }
}
