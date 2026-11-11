# SerwerAuth — logowanie dla Paper 1.21.x

Plugin logowania i rejestracji z captchą, weryfikacją ruchu i silną polityką haseł. Wiadomości po polsku.

## Budowanie

Wymagania: Java 21 i Maven.

```
mvn clean package
```

Gotowy plik: `target/SerwerAuth-1.0.0.jar` → wrzuć do `plugins/` i zrestartuj serwer.

## Przebieg wejścia gracza

1. **Captcha** — obrazek 128×128 na mapie w ręce (losowe obrócone znaki, krzywe linie, szum, falowe zniekształcenie). Gracz wpisuje `/captcha <kod>`. Zły kod = nowy kod; po 3 błędach kick.
2. **Rejestracja** (`/register <hasło> <powtórz>`) lub **logowanie** (`/login <hasło>`).
3. **Weryfikacja ruchu** — „Weryfikacja pozycji! Zacznij się poruszać! (1/5)”: gracz musi wykonać 5 kroków i ruszyć kamerą. Skoki/teleporty nie liczą się, jest limit strefy i czasu.
4. Dopiero wtedy gracz jest wolny, a na czacie pojawia się komunikat o dołączeniu.

Do końca weryfikacji zablokowane są: ruch, czat, komendy (poza logowaniem), interakcje, ekwipunek, obrażenia.

## Bezpieczeństwo

- Hasła: **PBKDF2-HMAC-SHA256**, 210 000 iteracji, losowa sól, porównanie w stałym czasie, automatyczny rehash po zmianie konfiguracji.
- Polityka haseł: min. 10 znaków, wielka i mała litera, cyfra, znak specjalny, bez spacji, bez nicku, bez popularnych haseł (także wersje „leet”, np. `P@ssw0rd`), bez `aaa` i ciągów `1234`/`abcd`/`qwer`.
- Blokada prób z eskalacją (osobno dla nicku i IP): 5 błędów → 2 min, potem 4, 8… maks. 1 h.
- Limit połączeń na IP/minutę, limit kont na IP, walidacja nicku, wymuszenie tej samej wielkości liter nicku.
- Hasła nie trafiają do logów konsoli (filtr log4j).
- Baza SQLite (`plugins/SerwerAuth/konta.db`), wszystkie operacje poza głównym wątkiem.
- Ekwipunek gracza jest zabezpieczony kopią w pliku na czas wyświetlania mapy captcha (także po awarii serwera).

## Komendy

| Komenda | Opis |
|---|---|
| `/login <hasło>` (`/l`) | logowanie |
| `/register <hasło> <hasło>` (`/reg`) | rejestracja |
| `/captcha <kod>` (`/kod`) | rozwiązanie captchy |
| `/changepassword <stare> <nowe>` | zmiana hasła |
| `/unregister <hasło>` | usunięcie konta |
| `/premium [wylacz]` | oznaczenie konta jako premium (weryfikacja nicku w Mojang) |
| `/auth reload` / `info <nick>` / `usun <nick>` | administracja (`serwerauth.admin`) |

## Konta premium — ważne ograniczenie

Prawdziwe „wejście premium bez hasła” wymaga kryptograficznego potwierdzenia właściciela konta Mojang (szyfrowany handshake), którego Paper w trybie offline nie udostępnia pluginom. Dlatego:

- `/premium` oznacza konto i sprawdza w API Mojang, czy nick istnieje jako konto premium,
- **auto-logowanie premium działa dopiero po podłączeniu weryfikatora** (`SerwerAuthApi.registerPremiumVerifier(...)`), np. proxy Velocity w trybie online + FastLogin,
- bez weryfikatora konta premium nadal logują się hasłem — nikt nie wejdzie na cudzy nick bez hasła.

## Konfiguracja

Wszystko w `plugins/SerwerAuth/config.yml` (opisane komentarzami) i `messages.yml` (MiniMessage). Zmiany: `/auth reload`.

## API dla innych pluginów

```java
SerwerAuthApi.isAuthenticated(player);
SerwerAuthApi.registerPremiumVerifier(player -> /* Twoja weryfikacja */ false);
```
