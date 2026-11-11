package pl.serwerauth.config;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/** Wiadomości z messages.yml w formacie MiniMessage. */
public final class Messages {

    private static final MiniMessage MM = MiniMessage.miniMessage();

    private final JavaPlugin plugin;
    private YamlConfiguration cfg;

    public Messages(JavaPlugin plugin) {
        this.plugin = plugin;
        reload();
    }

    public void reload() {
        File file = new File(plugin.getDataFolder(), "messages.yml");
        if (!file.exists()) {
            plugin.saveResource("messages.yml", false);
        }
        cfg = YamlConfiguration.loadConfiguration(file);
        try (InputStream in = plugin.getResource("messages.yml")) {
            if (in != null) {
                cfg.setDefaults(YamlConfiguration.loadConfiguration(new InputStreamReader(in, StandardCharsets.UTF_8)));
            }
        } catch (IOException ignored) {
        }
    }

    private String raw(String key) {
        String s = cfg.getString(key);
        return s == null ? "<red>[brak wiadomości: " + key + "]" : s;
    }

    /** Wiadomość z prefiksem. */
    public Component prefixed(String key, TagResolver... resolvers) {
        return MM.deserialize(raw("prefix") + raw(key), resolvers);
    }

    /** Wiadomość bez prefiksu (kicki, action bar, linie list). */
    public Component plain(String key, TagResolver... resolvers) {
        return MM.deserialize(raw(key), resolvers);
    }

    public void send(CommandSender to, String key, TagResolver... resolvers) {
        to.sendMessage(prefixed(key, resolvers));
    }

    public static TagResolver ph(String name, Object value) {
        return Placeholder.unparsed(name, String.valueOf(value));
    }
}
