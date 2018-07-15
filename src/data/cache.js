type CacheEntry<T> = {
    ttl: number;
    value: T;
}

export class MemoryCache {
    data: Map<string, CacheEntry>;

    get<T>(key: string): CacheEntry<T> {
        let entry = this.data.get(key).value;
        if (entry) {

        }

    }

    set<T>(key: string, value: CacheEntry<T>) {
        this.data.set(key, value);
    }
}