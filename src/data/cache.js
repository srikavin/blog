// @flow
type CacheEntry<T> = {
    added: Date,
    ttl: number;
    value: T;
}

export class MemoryCache<K, V> {
    data: Map<K, CacheEntry<V>>;

    constructor() {
        setInterval(() => {
            let now = new Date();
            this.data.forEach((value, key, map) => {
                let diff = now - value.added;
                if (diff > value.ttl * 1000) {
                    map.delete(key);
                }
            });

        }, 1000 * 30);
        this.data = new Map();
    }

    get(key: K): ?V {
        let entry = this.data.get(key);
        if (!entry) {
            return undefined;
        }
        return entry.value;
    }

    set(key: K, value: V, ttl: number = 60 * 5) {
        let entry = {
            added: new Date(),
            ttl,
            value
        };
        this.data.set(key, entry);
    }
}