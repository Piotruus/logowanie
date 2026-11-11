package pl.serwerauth.auth;

import net.kyori.adventure.text.Component;
import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.Sound;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.scheduler.BukkitTask;
import pl.serwerauth.SerwerAuth;
import pl.serwerauth.captcha.CaptchaMap;
import pl.serwerauth.config.Messages;
import pl.serwerauth.premium.PremiumService;
import pl.serwerauth.security.AttemptLimiter;
import pl.serwerauth.security.CaptchaGenerator;
import pl.serwerauth.security.ConnectionThrottle;
import pl.serwerauth.security.PasswordHasher;
import pl.serwerauth.security.PasswordPolicy;
import pl.serwerauth.storage.Account;
import pl.serwerauth.storage.Database;
import pl.serwerauth.util.TimeFormat;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.regex.Pattern;

import static pl.serwerauth.config.Messages.ph;

/**
 * Przebieg: wejście → captcha → logowanie / rejestracja → weryfikacja ruchu → GOTOWY.
 * Każdy etap poza GOTOWY blokuje gracza (ruch, czat, komendy, interakcje).
 */
public final class AuthManager {

    public enum Stage { LADOWANIE, CAPTCHA, LOGIN, REJESTRACJA, RUCH, GOTOWY }

    private static final class PlayerState {
        final String name;
        final long joinedAt = System.currentTimeMillis();
        volatile Stage stage = Stage.LADOWANIE;
        volatile boolean busy;
        Account account;
        boolean prevInvulnerable;
        BukkitTask task;
        // captcha
        String captchaCode;
        int captchaFails;
        // weryfikacja ruchu
        Location start;
        double anchorX, anchorZ;
        int steps;
        long lastStepAt;
        long moveStartedAt;
        float yawAccum;
        boolean yawHinted;

        PlayerState(String name) {
            this.name = name;
        }
    }

    private record Session(String ip, long expiresAt) {
    }

    private record Verify(boolean ok, String newHash) {
    }

    private final SerwerAuth plugin;
    private final Database db;
    private final Messages msg;
    private final PremiumService premium;
    private final CaptchaMap captchaMap;
    private final Map<UUID, PlayerState> states = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final ExecutorService hashPool = Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "SerwerAuth-Hash");
        t.setDaemon(true);
        return t;
    });

    private volatile AttemptLimiter ipLimiter;
    private volatile AttemptLimiter nickLimiter;
    private volatile ConnectionThrottle throttle;
    private volatile Pattern nickPattern;

    public AuthManager(SerwerAuth plugin, Database db, Messages msg, PremiumService premium, CaptchaMap captchaMap) {
        this.plugin = plugin;
        this.db = db;
        this.msg = msg;
        this.premium = premium;
        this.captchaMap = captchaMap;
        reloadSettings();
    }

    private FileConfiguration cfg() {
        return plugin.getConfig();
    }

    /** Buduje limitery na nowo (po /auth reload; blokady są wtedy zerowane). */
    public void reloadSettings() {
        FileConfiguration c = cfg();
        int maxFails = c.getInt("logowanie.maks-prob-hasla", 5);
        long lockMs = c.getLong("logowanie.blokada-sekundy", 120) * 1000L;
        ipLimiter = new AttemptLimiter(maxFails, lockMs);
        nickLimiter = new AttemptLimiter(maxFails, lockMs);
        throttle = new ConnectionThrottle(c.getInt("polaczenia.maks-na-minute-z-ip", 6), 60_000L);
        try {
            nickPattern = Pattern.compile(c.getString("polaczenia.nick-regex", "^[A-Za-z0-9_]{3,16}$"));
        } catch (Exception e) {
            nickPattern = Pattern.compile("^[A-Za-z0-9_]{3,16}$");
        }
    }

    // ------------------------------------------------------------------ pomocnicze

    public void sync(Runnable r) {
        if (!plugin.isEnabled()) return;
        if (Bukkit.isPrimaryThread()) r.run();
        else Bukkit.getScheduler().runTask(plugin, r);
    }

    private static String ip(Player p) {
        return p.getAddress() != null ? p.getAddress().getAddress().getHostAddress() : "unknown";
    }

    private static String nickKey(String name) {
        return "nick:" + name.toLowerCase(Locale.ROOT);
    }

    private void logError(String what, Throwable t) {
        plugin.getLogger().log(Level.SEVERE, what, t instanceof java.util.concurrent.CompletionException && t.getCause() != null ? t.getCause() : t);
    }

    public boolean isLocked(Player p) {
        PlayerState st = states.get(p.getUniqueId());
        return st != null && st.stage != Stage.GOTOWY;
    }

    public boolean isAuthenticated(Player p) {
        PlayerState st = states.get(p.getUniqueId());
        return st != null && st.stage == Stage.GOTOWY;
    }

    public Stage stageOf(Player p) {
        PlayerState st = states.get(p.getUniqueId());
        return st == null ? null : st.stage;
    }

    public boolean allowConnection(String ip) {
        return throttle.allow(ip);
    }

    public Pattern nickPattern() {
        return nickPattern;
    }

    /** Pozostały czas blokady dla IP lub nicku (ms). */
    public long lockRemaining(String ip, String name) {
        return Math.max(ipLimiter.remainingMs(ip), nickLimiter.remainingMs(nickKey(name)));
    }

    public void cleanup() {
        ipLimiter.cleanup();
        nickLimiter.cleanup();
        throttle.cleanup();
        long now = System.currentTimeMillis();
        sessions.entrySet().removeIf(e -> e.getValue().expiresAt() < now);
    }

    /** Wyrzuca gracza z komunikatem i usuwa jego sesję. */
    public void forgetSession(String name) {
        sessions.remove(name.toLowerCase(Locale.ROOT));
    }

    // ------------------------------------------------------------------ wejście / wyjście

    public void onJoin(Player p) {
        UUID id = p.getUniqueId();
        PlayerState st = new PlayerState(p.getName());
        states.put(id, st);

        captchaMap.recover(p);
        st.prevInvulnerable = p.isInvulnerable();
        p.setInvulnerable(true);
        st.task = Bukkit.getScheduler().runTaskTimer(plugin, () -> tick(p, st), 20L, 20L);

        db.find(p.getName()).whenComplete((opt, err) -> sync(() -> {
            if (states.get(id) != st || !p.isOnline()) return;
            if (err != null) {
                logError("Błąd odczytu konta " + p.getName(), err);
                p.kick(msg.plain("kick.blad-bazy"));
                return;
            }
            st.account = opt.orElse(null);
            decideFlow(p, st);
        }));
    }

    public void onQuit(Player p) {
        PlayerState st = states.remove(p.getUniqueId());
        if (st == null) return;
        if (st.task != null) st.task.cancel();
        captchaMap.hide(p);
        p.setInvulnerable(st.prevInvulnerable);
    }

    public void shutdown() {
        for (Player p : Bukkit.getOnlinePlayers()) {
            onQuit(p);
        }
        hashPool.shutdownNow();
        sessions.clear();
    }

    private void tick(Player p, PlayerState st) {
        if (!p.isOnline() || st.stage == Stage.GOTOWY) {
            if (st.task != null) st.task.cancel();
            return;
        }
        long now = System.currentTimeMillis();
        if (st.stage == Stage.RUCH) {
            long limit = cfg().getLong("weryfikacja-ruchu.czas", 30) * 1000L;
            if (now - st.moveStartedAt > limit) {
                p.kick(msg.plain("kick.ruch-czas"));
                return;
            }
        } else {
            long limit = cfg().getLong("logowanie.czas-na-zalogowanie", 90) * 1000L;
            if (now - st.joinedAt > limit) {
                p.kick(msg.plain("kick.czas"));
                return;
            }
        }
        Component bar = switch (st.stage) {
            case CAPTCHA -> msg.plain("actionbar.captcha");
            case LOGIN -> msg.plain("actionbar.login");
            case REJESTRACJA -> msg.plain("actionbar.rejestracja");
            case RUCH -> msg.plain("actionbar.ruch",
                    ph("krok", Math.min(st.steps + 1, need())), ph("max", need()));
            default -> null;
        };
        if (bar != null) p.sendActionBar(bar);
    }

    private int need() {
        return Math.max(1, cfg().getInt("weryfikacja-ruchu.kroki", 5));
    }

    // ------------------------------------------------------------------ przebieg

    private void decideFlow(Player p, PlayerState st) {
        String ip = ip(p);
        Account acc = st.account;
        if (acc != null && acc.premium() && premium.isVerified(p)) {
            db.touchLogin(st.name, ip);
            finish(p, st);
            return;
        }
        if (acc != null) {
            Session s = sessions.get(st.name.toLowerCase(Locale.ROOT));
            if (s != null && s.ip().equals(ip) && s.expiresAt() > System.currentTimeMillis()) {
                db.touchLogin(st.name, ip);
                msg.send(p, "login.sesja");
                finish(p, st);
                return;
            }
        }
        if (cfg().getBoolean("captcha.wlaczona", true)) {
            st.stage = Stage.CAPTCHA;
            st.captchaFails = 0;
            newCaptcha(p, st);
        } else {
            beginAuth(p, st);
        }
    }

    private void newCaptcha(Player p, PlayerState st) {
        String code = CaptchaGenerator.randomCode(Math.max(3, cfg().getInt("captcha.dlugosc", 5)));
        st.captchaCode = code;
        boolean map = "MAPA".equalsIgnoreCase(cfg().getString("captcha.tryb", "MAPA")) && captchaMap.show(p, code);
        if (map) {
            msg.send(p, "captcha.mapa");
        } else {
            msg.send(p, "captcha.czat", ph("kod", code));
        }
    }

    public void submitCaptcha(Player p, String input) {
        PlayerState st = states.get(p.getUniqueId());
        if (st == null) return;
        if (st.stage != Stage.CAPTCHA || st.captchaCode == null) {
            msg.send(p, "captcha.nie-teraz");
            return;
        }
        if (st.captchaCode.equalsIgnoreCase(input.trim())) {
            st.captchaCode = null;
            captchaMap.hide(p);
            msg.send(p, "captcha.ok");
            beginAuth(p, st);
            return;
        }
        st.captchaFails++;
        int left = Math.max(1, cfg().getInt("captcha.maks-prob", 3)) - st.captchaFails;
        if (left <= 0) {
            ipLimiter.fail(ip(p));
            p.kick(msg.plain("kick.captcha"));
            return;
        }
        msg.send(p, "captcha.zle", ph("pozostalo", left));
        newCaptcha(p, st);
    }

    private void beginAuth(Player p, PlayerState st) {
        if (st.account == null) {
            st.stage = Stage.REJESTRACJA;
            msg.send(p, "register.zarejestruj", ph("nick", st.name));
        } else {
            st.stage = Stage.LOGIN;
            msg.send(p, "login.zaloguj", ph("nick", st.name));
        }
    }

    public void login(Player p, String password) {
        PlayerState st = states.get(p.getUniqueId());
        if (st == null) return;
        switch (st.stage) {
            case GOTOWY, RUCH -> {
                msg.send(p, "login.juz");
                return;
            }
            case LADOWANIE, CAPTCHA -> {
                msg.send(p, "login.najpierw-captcha");
                return;
            }
            case REJESTRACJA -> {
                msg.send(p, "login.brak-konta");
                return;
            }
            default -> {
            }
        }
        if (st.busy) return;
        String ip = ip(p);
        String nk = nickKey(st.name);
        long wait = Math.max(ipLimiter.remainingMs(ip), nickLimiter.remainingMs(nk));
        if (wait > 0) {
            p.kick(msg.plain("kick.zablokowano", ph("czas", TimeFormat.format(wait))));
            return;
        }
        Account acc = st.account;
        int iterations = cfg().getInt("haslo.iteracje-pbkdf2", 210000);
        st.busy = true;
        CompletableFuture.supplyAsync(() -> {
            boolean ok = PasswordHasher.verify(acc.hash(), password);
            String newHash = ok && PasswordHasher.needsRehash(acc.hash(), iterations)
                    ? PasswordHasher.hash(password, iterations) : null;
            return new Verify(ok, newHash);
        }, hashPool).whenComplete((res, err) -> sync(() -> {
            st.busy = false;
            if (states.get(p.getUniqueId()) != st || !p.isOnline()) return;
            if (err != null) {
                logError("Błąd weryfikacji hasła", err);
                msg.send(p, "blad");
                return;
            }
            if (!res.ok()) {
                int left = Math.min(ipLimiter.fail(ip), nickLimiter.fail(nk));
                if (left <= 0) {
                    long w = Math.max(ipLimiter.remainingMs(ip), nickLimiter.remainingMs(nk));
                    p.kick(msg.plain("kick.zablokowano", ph("czas", TimeFormat.format(w))));
                } else {
                    msg.send(p, "login.zle-haslo", ph("pozostalo", left));
                }
                return;
            }
            ipLimiter.reset(ip);
            nickLimiter.reset(nk);
            if (res.newHash() != null) {
                db.updateHash(st.name, res.newHash()).exceptionally(t -> {
                    logError("Nie udało się zaktualizować hasha", t);
                    return null;
                });
            }
            db.touchLogin(st.name, ip);
            msg.send(p, "login.ok");
            afterAuth(p, st);
        }));
    }

    public void register(Player p, String pw, String pw2) {
        PlayerState st = states.get(p.getUniqueId());
        if (st == null) return;
        switch (st.stage) {
            case GOTOWY, RUCH -> {
                msg.send(p, "login.juz");
                return;
            }
            case LADOWANIE, CAPTCHA -> {
                msg.send(p, "login.najpierw-captcha");
                return;
            }
            case LOGIN -> {
                msg.send(p, "register.masz-konto");
                return;
            }
            default -> {
            }
        }
        if (st.busy) return;
        if (!pw.equals(pw2)) {
            msg.send(p, "register.haslo-rozne");
            return;
        }
        int min = cfg().getInt("haslo.min-dlugosc", 10);
        int max = cfg().getInt("haslo.max-dlugosc", 64);
        if (!checkPolicy(p, pw, st.name, min, max)) return;

        String ip = ip(p);
        int maxAccounts = cfg().getInt("haslo.maks-kont-na-ip", 3);
        int iterations = cfg().getInt("haslo.iteracje-pbkdf2", 210000);
        st.busy = true;
        db.countByIp(ip).thenCompose(count -> {
            if (count >= maxAccounts) {
                return CompletableFuture.<Account>completedFuture(null);
            }
            return CompletableFuture.supplyAsync(() -> PasswordHasher.hash(pw, iterations), hashPool).thenCompose(hash -> {
                long now = System.currentTimeMillis();
                Account acc = new Account(st.name, hash, false, null, ip, ip, now, now);
                return db.create(acc).thenApply(v -> acc);
            });
        }).whenComplete((acc, err) -> sync(() -> {
            st.busy = false;
            if (states.get(p.getUniqueId()) != st || !p.isOnline()) return;
            if (err != null) {
                logError("Błąd rejestracji konta " + st.name, err);
                msg.send(p, "blad");
                return;
            }
            if (acc == null) {
                msg.send(p, "register.limit-kont");
                return;
            }
            st.account = acc;
            msg.send(p, "register.ok");
            afterAuth(p, st);
        }));
    }

    private boolean checkPolicy(Player p, String pw, String nick, int min, int max) {
        List<PasswordPolicy.Problem> problems = PasswordPolicy.validate(pw, nick, min, max);
        if (problems.isEmpty()) return true;
        msg.send(p, "polityka.naglowek");
        for (PasswordPolicy.Problem pr : problems) {
            p.sendMessage(msg.plain(pr.key(), ph("min", min), ph("max", max)));
        }
        return false;
    }

    public void changePassword(Player p, String oldPw, String newPw) {
        PlayerState st = states.get(p.getUniqueId());
        if (st == null || st.stage != Stage.GOTOWY || st.account == null) {
            msg.send(p, "login.nie-teraz");
            return;
        }
        if (st.busy) return;
        int min = cfg().getInt("haslo.min-dlugosc", 10);
        int max = cfg().getInt("haslo.max-dlugosc", 64);
        if (!checkPolicy(p, newPw, st.name, min, max)) return;
        if (oldPw.equals(newPw)) {
            msg.send(p, "zmiana.takie-samo");
            return;
        }
        String nk = nickKey(st.name);
        long wait = nickLimiter.remainingMs(nk);
        if (wait > 0) {
            msg.send(p, "login.zablokowano", ph("czas", TimeFormat.format(wait)));
            return;
        }
        Account acc = st.account;
        int iterations = cfg().getInt("haslo.iteracje-pbkdf2", 210000);
        st.busy = true;
        CompletableFuture.supplyAsync(
                        () -> PasswordHasher.verify(acc.hash(), oldPw) ? PasswordHasher.hash(newPw, iterations) : null, hashPool)
                .thenCompose(hash -> hash == null
                        ? CompletableFuture.<String>completedFuture(null)
                        : db.updateHash(st.name, hash).thenApply(v -> hash))
                .whenComplete((hash, err) -> sync(() -> {
                    st.busy = false;
                    if (states.get(p.getUniqueId()) != st || !p.isOnline()) return;
                    if (err != null) {
                        logError("Błąd zmiany hasła", err);
                        msg.send(p, "blad");
                        return;
                    }
                    if (hash == null) {
                        int left = nickLimiter.fail(nk);
                        if (left <= 0) {
                            p.kick(msg.plain("kick.zablokowano", ph("czas", TimeFormat.format(nickLimiter.remainingMs(nk)))));
                        } else {
                            msg.send(p, "zmiana.stare-zle", ph("pozostalo", left));
                        }
                        return;
                    }
                    nickLimiter.reset(nk);
                    st.account = acc.withHash(hash);
                    msg.send(p, "zmiana.ok");
                }));
    }

    public void unregister(Player p, String password) {
        PlayerState st = states.get(p.getUniqueId());
        if (st == null || st.stage != Stage.GOTOWY || st.account == null) {
            msg.send(p, "login.nie-teraz");
            return;
        }
        if (st.busy) return;
        String nk = nickKey(st.name);
        long wait = nickLimiter.remainingMs(nk);
        if (wait > 0) {
            msg.send(p, "login.zablokowano", ph("czas", TimeFormat.format(wait)));
            return;
        }
        Account acc = st.account;
        st.busy = true;
        CompletableFuture.supplyAsync(() -> PasswordHasher.verify(acc.hash(), password), hashPool)
                .thenCompose(ok -> ok ? db.delete(st.name) : CompletableFuture.completedFuture(Boolean.FALSE))
                .whenComplete((deleted, err) -> sync(() -> {
                    st.busy = false;
                    if (states.get(p.getUniqueId()) != st || !p.isOnline()) return;
                    if (err != null) {
                        logError("Błąd usuwania konta", err);
                        msg.send(p, "blad");
                        return;
                    }
                    if (!deleted) {
                        int left = nickLimiter.fail(nk);
                        if (left <= 0) {
                            p.kick(msg.plain("kick.zablokowano", ph("czas", TimeFormat.format(nickLimiter.remainingMs(nk)))));
                        } else {
                            msg.send(p, "usuwanie.zle-haslo", ph("pozostalo", left));
                        }
                        return;
                    }
                    forgetSession(st.name);
                    p.kick(msg.plain("kick.konto-usuniete"));
                }));
    }

    // ------------------------------------------------------------------ weryfikacja ruchu

    private void afterAuth(Player p, PlayerState st) {
        if (cfg().getBoolean("weryfikacja-ruchu.wlaczona", true)) {
            beginMovement(p, st);
        } else {
            finish(p, st);
        }
    }

    private void beginMovement(Player p, PlayerState st) {
        st.stage = Stage.RUCH;
        st.start = p.getLocation().clone();
        st.anchorX = st.start.getX();
        st.anchorZ = st.start.getZ();
        st.steps = 0;
        st.lastStepAt = 0L;
        st.yawAccum = 0f;
        st.yawHinted = false;
        st.moveStartedAt = System.currentTimeMillis();
        p.sendMessage(msg.plain("ruch.start", ph("krok", 1), ph("max", need())));
    }

    /** Wołane z PlayerMoveEvent: blokuje ruch przed weryfikacją albo liczy kroki podczas weryfikacji ruchu. */
    public void handleMove(PlayerMoveEvent e) {
        Player p = e.getPlayer();
        PlayerState st = states.get(p.getUniqueId());
        if (st == null || st.stage == Stage.GOTOWY) return;
        Location from = e.getFrom();
        Location to = e.getTo();
        if (to == null) return;

        if (st.stage == Stage.RUCH) {
            track(e, p, st, from, to);
            return;
        }
        if (from.getX() != to.getX() || from.getY() != to.getY() || from.getZ() != to.getZ()) {
            Location back = from.clone();
            back.setYaw(to.getYaw());
            back.setPitch(to.getPitch());
            e.setTo(back); // pozycja zablokowana, rozglądanie się dozwolone
        }
    }

    private void track(PlayerMoveEvent e, Player p, PlayerState st, Location from, Location to) {
        if (from.getWorld() != to.getWorld()) return;
        FileConfiguration c = cfg();
        int need = need();

        float dyaw = Math.abs(to.getYaw() - from.getYaw()) % 360f;
        if (dyaw > 180f) dyaw = 360f - dyaw;
        st.yawAccum += dyaw;

        double moved = Math.hypot(to.getX() - from.getX(), to.getZ() - from.getZ());
        if (moved > c.getDouble("weryfikacja-ruchu.maks-skok", 4.0)) {
            // teleport / glitch — nie liczymy, tylko resetujemy punkt odniesienia
            st.anchorX = to.getX();
            st.anchorZ = to.getZ();
            return;
        }

        double fromStart = Math.hypot(to.getX() - st.start.getX(), to.getZ() - st.start.getZ());
        if (fromStart > c.getDouble("weryfikacja-ruchu.promien", 8.0)) {
            Location back = st.start.clone();
            back.setYaw(to.getYaw());
            back.setPitch(to.getPitch());
            e.setTo(back);
            st.anchorX = back.getX();
            st.anchorZ = back.getZ();
            msg.send(p, "ruch.strefa");
            return;
        }

        long now = System.currentTimeMillis();
        if (st.steps < need) {
            double dist = Math.hypot(to.getX() - st.anchorX, to.getZ() - st.anchorZ);
            if (dist >= c.getDouble("weryfikacja-ruchu.min-dystans", 0.9)
                    && now - st.lastStepAt >= c.getLong("weryfikacja-ruchu.min-odstep-ms", 350)) {
                st.steps++;
                st.lastStepAt = now;
                st.anchorX = to.getX();
                st.anchorZ = to.getZ();
                p.sendActionBar(msg.plain("ruch.krok", ph("krok", st.steps), ph("max", need)));
                p.playSound(p.getLocation(), Sound.BLOCK_NOTE_BLOCK_PLING, 0.6f, 0.7f + 0.1f * st.steps);
            }
        }

        if (st.steps >= need) {
            boolean needYaw = c.getBoolean("weryfikacja-ruchu.wymagaj-obrotu", true);
            double minYaw = c.getDouble("weryfikacja-ruchu.min-obrot-stopni", 20.0);
            if (!needYaw || st.yawAccum >= minYaw) {
                finish(p, st);
            } else if (!st.yawHinted) {
                st.yawHinted = true;
                msg.send(p, "ruch.obrot");
            }
        }
    }

    private void finish(Player p, PlayerState st) {
        st.stage = Stage.GOTOWY;
        if (st.task != null) st.task.cancel();
        captchaMap.hide(p);
        p.setInvulnerable(st.prevInvulnerable);
        p.sendActionBar(Component.empty());

        long minutes = cfg().getLong("logowanie.sesja-minuty", 0);
        if (minutes > 0) {
            sessions.put(st.name.toLowerCase(Locale.ROOT), new Session(ip(p), System.currentTimeMillis() + minutes * 60_000L));
        }
        p.sendMessage(msg.plain("ruch.ok"));
        p.playSound(p.getLocation(), Sound.ENTITY_PLAYER_LEVELUP, 0.6f, 1.2f);
        if (cfg().getBoolean("ukryj-komunikaty-dolaczenia", true)) {
            Bukkit.broadcast(msg.plain("dolaczyl", ph("nick", p.getName())));
        }
    }
}
