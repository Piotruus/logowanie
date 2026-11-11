package pl.serwerauth.security;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Limit nieudanych prób z eskalacją: po {@code maxFails} błędach blokada na {@code baseLockMs},
 * a każda kolejna blokada trwa dwa razy dłużej (maks. 1 godzina).
 */
public final class AttemptLimiter {

    private static final long MAX_LOCK_MS = 3_600_000L;
    private static final long FORGET_AFTER_MS = 24L * 3_600_000L;

    private record Entry(int fails, int lockouts, long lockedUntil, long lastFail) {
    }

    private final ConcurrentHashMap<String, Entry> map = new ConcurrentHashMap<>();
    private final int maxFails;
    private final long baseLockMs;

    public AttemptLimiter(int maxFails, long baseLockMs) {
        this.maxFails = Math.max(1, maxFails);
        this.baseLockMs = Math.max(1000L, baseLockMs);
    }

    /** Ile milisekund zostało do końca blokady (0 = brak blokady). */
    public long remainingMs(String key) {
        Entry e = map.get(key);
        if (e == null) return 0L;
        return Math.max(0L, e.lockedUntil() - System.currentTimeMillis());
    }

    /** Rejestruje błąd. Zwraca liczbę pozostałych prób; 0 oznacza, że właśnie nałożono blokadę. */
    public int fail(String key) {
        int[] remaining = new int[1];
        map.compute(key, (k, cur) -> {
            long now = System.currentTimeMillis();
            Entry e = cur == null ? new Entry(0, 0, 0L, now) : cur;
            int fails = e.fails() + 1;
            if (fails >= maxFails) {
                long lock = Math.min(baseLockMs << Math.min(e.lockouts(), 10), MAX_LOCK_MS);
                remaining[0] = 0;
                return new Entry(0, e.lockouts() + 1, now + lock, now);
            }
            remaining[0] = maxFails - fails;
            return new Entry(fails, e.lockouts(), e.lockedUntil(), now);
        });
        return remaining[0];
    }

    public void reset(String key) {
        map.remove(key);
    }

    /** Usuwa stare wpisy (wołane okresowo). */
    public void cleanup() {
        long now = System.currentTimeMillis();
        map.entrySet().removeIf(en -> now - Math.max(en.getValue().lastFail(), en.getValue().lockedUntil()) > FORGET_AFTER_MS);
    }
}
