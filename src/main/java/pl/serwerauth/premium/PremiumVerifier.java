package pl.serwerauth.premium;

import org.bukkit.entity.Player;

/**
 * Punkt integracji z zewnętrznym mechanizmem, który POTRAFI kryptograficznie potwierdzić,
 * że gracz jest właścicielem konta Mojang (np. serwer proxy w trybie online + plugin FastLogin).
 * Paper w trybie offline sam tego nie umie — bez weryfikatora konta premium nadal logują się hasłem.
 */
@FunctionalInterface
public interface PremiumVerifier {
    boolean isVerified(Player player);
}
