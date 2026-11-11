package pl.serwerauth.api;

import org.bukkit.entity.Player;
import pl.serwerauth.SerwerAuth;
import pl.serwerauth.premium.PremiumVerifier;

/** API dla innych pluginów. */
public final class SerwerAuthApi {

    private SerwerAuthApi() {
    }

    /** Czy gracz przeszedł pełną weryfikację (captcha, logowanie, ruch). */
    public static boolean isAuthenticated(Player player) {
        SerwerAuth plugin = SerwerAuth.getInstance();
        return plugin != null && plugin.auth().isAuthenticated(player);
    }

    /** Rejestruje zewnętrzny weryfikator premium (patrz {@link PremiumVerifier}). */
    public static void registerPremiumVerifier(PremiumVerifier verifier) {
        SerwerAuth plugin = SerwerAuth.getInstance();
        if (plugin != null) {
            plugin.premium().setVerifier(verifier);
        }
    }
}
