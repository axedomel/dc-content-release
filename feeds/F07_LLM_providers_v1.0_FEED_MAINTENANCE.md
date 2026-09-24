# F.07 Feed Maintenance Guide
**Pack:** LLM & AI Detection Pack v0.9
**Cycle:** Monthly review + event-triggered updates

---

## Struktura kategorii

| threat.category | Zakres | Trigger w AR |
|---|---|---|
| `llm-provider` | Consumer AI: OpenAI, Anthropic, Gemini, Mistral... | eoc/boc (visibility) |
| `llm-enterprise` | Azure OpenAI, AWS Bedrock, GCP Vertex, IBM watsonx... | eoc/boc (visibility) |
| `llm-coding` | GitHub Copilot, Cursor, Tabnine, Codeium... | boc (IP exfil risk) |
| `llm-malicious` | WormGPT, FraudGPT, GhostGPT, underground AI... | **ioc (natychmiastowy alert)** |

Zasada: dodanie nowego providera = **jeden wiersz w CSV**. Zero zmian w AR.

---

## Źródła aktualizacji

### 1. Automatyczne — Certificate Transparency
Nowe serwisy AI zawsze dostają TLS cert. Monitoruj:
- https://crt.sh/?q=%25api%25ai%25 — certyfikaty z "api" i "ai" w nazwie
- https://crt.sh/?q=%25llm%25 — certyfikaty z "llm"
- https://crt.sh/?q=%25gpt%25 — certyfikaty z "gpt"
Nowy cert od nieznanego AI serwisu = kandydat do feeda.

### 2. Community — GitHub
- github.com/danielmiessler/ai-urls — community-maintained lista AI endpoints
- github.com/ai-collection/ai-collection — katalog AI serwisów
Sprawdzaj diff od ostatniej aktualizacji, dodawaj nowe API endpointy.

### 3. Enterprise — vendor release notes (kwartalne)
- Azure: aka.ms/azure-ai-updates
- AWS: aws.amazon.com/new (filtr: AI/ML)
- GCP: cloud.google.com/release-notes
Nowy region bedrock / nowy Azure AI endpoint = nowy wpis.

### 4. Darknet / Malicious — threat intel (miesięczne)
Źródła monitorujące underground AI-as-a-service:
- Recorded Future blog: recordedfuture.com/research
- Flashpoint: flashpoint.io/blog
- KELA Research: ke-la.com/blog
- Dark Owl, Intel471 (jeśli dostępne)

Znane rodziny do śledzenia: WormGPT, FraudGPT, GhostGPT, EvilGPT,
DarkGPT, LabRAT, XXXGPT, BlackhatGPT i ich kolejne wersje.
Domeny rotują co 2-6 tygodni — stare wpisy zostaw (historyczne
śledztwa), nowe dodawaj.

### 5. Event-triggered — niezwłocznie
Dodaj wpis od razu gdy:
- Nowy major AI provider ogłasza publiczne API
- Threat intel raportuje nową malicious AI usługę z konkretną domeną
- Klient zgłasza ruch do nieznanego AI endpointu

---

## Procedura aktualizacji

```
1. Pobierz aktualny F_07_ai_providers_vX.Y.csv
2. Dodaj nowe wpisy na końcu odpowiedniej sekcji
3. Zmień threat.source na nową wersję (np. nw-llm-v0.9)
4. Zaktualizuj datę w komentarzu nagłówka
5. Załaduj CSV jako feed na Decoder (zastąp poprzedni)
6. Weryfikacja: Investigate → threat.category exists → sprawdź nowe wpisy
7. Zaktualizuj wersję w dokumentacji paczki
```

Nie usuwaj starych wpisów — threat.source pozwala śledzić kiedy
co zostało dodane. Przy wpisach malicious: nieaktywne domeny
pozostają w CSV jako historyczny kontekst dla śledztw.

---

## Format CSV

```
host,threat.category,threat.desc,threat.source
api.newprovider.com,llm-provider,NewProvider API,nw-llm-v0.9
```

- Brak wildcardów — tylko pełne FQDN
- Brak nagłówka przy imporcie w starszych wersjach NW (sprawdź wersję)
- Komentarze (#) — pomijane przez parser NW od v12.3+
- threat.source = wersja pliku (pozwala filtrować w Investigate)

---

# Strategia detekcji — feed czy nie feed?

Ta sekcja jest decyzyjna: jak wybierać metodę rozpoznawania dla nowej domeny
(LLM, Shadow SaaS, RMM, DoH itp.) tak, żeby minimalizować utrzymanie.

## Zasada nadrzędna: feed vs hardcoded to fałszywa alternatywa

Obie metody się starzeją. Różnica jest w tym jak naprawiasz starzenie:
- **Feed** — edytujesz CSV (łatwe), ale wymaga dystrybucji (rozwiązuje recurring feed)
- **Hardcoded w regule** — edytujesz regułę + reimport + redeploy do policy (boli)

Trzecia metoda nie starzeje się wcale: **detekcja behawioralna/protokołowa.**

## Hierarchia odporności na starzenie

```
1. BEHAWIORALNA / PROTOKOŁOWA   — nigdy się nie starzeje, zero utrzymania
   Keyuje na: wzorzec beacona, rozmiar sesji, port, sygnatura protokołu,
              brak user-agenta, timing. Nie obchodzi jej DOKĄD idzie ruch.
   Przykłady: DoH = POST do /dns-query; mining = Stratum mining.subscribe;
              RMM = port 6568 (AnyDesk) / 5938 (TeamViewer) + keepalive
   To jest fundament. Najlepsze live rules działają tak od lat.

2. FEED (identity)              — starzeje się, ale odświeżasz centralnie
   Keyuje na: threat.category z dopasowania alias.host przez feed
   Recurring feed = jedno źródło, auto-update u wszystkich klientów

3. HARDCODED identity w regule  — starzeje się ORAZ boli przy odświeżaniu
   Lista hostów wprost w warunku AR. Najgorsza z trzech dla rzeczy
   które się zmieniają. OK tylko dla krótkich stabilnych list.
```

## Reguła decyzyjna dla nowej domeny

### Krok 1 — Czy da się wykryć behawioralnie?
Jeśli domena ma sygnaturę protokołu, charakterystyczny port lub wzorzec sesji
→ buduj behawioralnie, BEZ żadnej listy. Zero utrzymania.

| Domena | Behawioralny sygnał (bez listy) |
|---|---|
| DoH | POST do /dns-query, content-type application/dns-message |
| Crypto mining | Stratum: mining.subscribe / mining.authorize w JSON-RPC |
| RMM (część) | porty: AnyDesk 6568, TeamViewer 5938, RustDesk 21115-21119 |
| Tunneling | długie połączenie + stały rozmiar pakietów + brak treści |
| Beacon C2 | regularny interwał + małe sesje + session size 0-5k |

### Krok 2 — Jeśli potrzebujesz tożsamości celu, oceń koszt starzenia
Niektóre domeny wymagają wiedzy "co to za host" (z zachowania nie odróżnisz
uploadu do OpenAI od uploadu do dowolnego API). Tu wybór feed vs hardcoded
według tego JAK SZYBKO lista się starzeje i JAKI jest koszt pominięcia:

| Typ listy | Tempo zmian | Koszt pominięcia | Metoda |
|---|---|---|---|
| Stabilna (dostawcy LLM, RMM tools) | wolne (miesiące) | niski (luka widoczności) | hardcoded LUB feed kwartalny |
| Wolatylna (malicious domains) | szybkie (tygodnie) | wysoki (dziura detekcji) | **feed (recurring)** |

### Krok 3 — Wartość feeda = rozmiar × liczba reguł × tempo zmian
Feed broni się gdy wszystkie trzy są wysokie:
- Duża lista (>20 wpisów) → hardcode byłby brzydki, łamie DRY
- Wiele reguł używa tej samej listy → feed = jedno źródło
- Lista rotuje → ręczna edycja reguł nie do utrzymania

LLM: 67 wpisów × 15 reguł × sekcja malicious rotuje → feed uzasadniony.
Krótka stabilna lista × 1 reguła × bez zmian → hardcode prostszy.

## Rekomendacja praktyczna

```
1. Domyślnie buduj behawioralnie — przesuń jak najwięcej do warstwy 1.
2. Tożsamość celu tylko gdy nieunikniona (LLM, SaaS).
3. W warstwie tożsamości: hardcode stabilne, feeduj tylko to co rotuje.
4. Feed rób recurring (patrz niżej) — wtedy starzenie przestaje boleć.
```

Dla LLM konkretnie: feed zostaje (67 wpisów uzasadnia), ale tylko sekcja
llm-malicious (~6 domen) wymaga częstego odświeżania. Reszta jest stabilna.
Nawet bez recurring feed — ręczna aktualizacja 6 wpisów/miesiąc to nic.

---

# Recurring feed — model dystrybucji

Rozwiązuje problem dystrybucji feeda: jedno źródło, auto-update u klientów.

## Jak działa

NetWitness pobiera feed z URL na harmonogramie:
```
Configure → Custom Feeds → Add → Recurring Feed
  URL:      https://raw.githubusercontent.com/<user>/nw-feeds/main/F07_ai_providers.csv
  Interval: dzienny (lub godzinowy dla threat-intel)
  Match:    alias.host
  Values:   threat.category, threat.desc, threat.source
```
Aktualizujesz GitHub → klienci dostają zmianę przy następnym cyklu.
Jedno źródło prawdy, zero ręcznej redystrybucji.

## Główny problem — egress Decodera

Wiele Decoderów jest w izolowanych segmentach bez dostępu do internetu.
Bezpośredni pull z GitHub wymaga outbound 443 do raw.githubusercontent.com.

**Wzorzec wewnętrznego mirrora** (zalecany dla środowisk z ograniczeniami):
```
Twój GitHub (master)
    └── pull przez wewnętrzny serwer klienta (review przed publikacją)
            └── Decoder pobiera recurring feed z wewnętrznego URL
```
Klient kontroluje co wchodzi, Decoder nie wychodzi do internetu,
ty dalej utrzymujesz jedno źródło. Dla klientów bez ograniczeń — pull wprost.

## Integralność repo

Decoder klienta ufa twojemu URL → przejęcie konta GitHub = wstrzyknięcie feeda.
Przy llm-malicious szczególnie wrażliwe (dodanie legalnej domeny jako malicious
= IOC storm). Minimum:
- dedykowane repo tylko na feedy
- 2FA na koncie GitHub
- ewentualnie signed commits
- wewnętrzny mirror u klienta dodatkowo ogranicza ryzyko

## Struktura repo (skaluje się na wiele paczek)

```
github.com/<user>/netwitness-feeds/
├── F07_ai_providers.csv      (LLM pack)
├── F14_saas_apps.csv         (Shadow SaaS — gdy powstanie)
├── F15_rmm_cloud_relays.csv  (RMM — tylko cloud-relayed, reszta behawioralnie)
├── F16_malicious_ai.csv      (rotująca threat-intel, pull godzinowy)
└── CHANGELOG.md
```
Klient konfiguruje recurring feed raz per domena którą wdraża.
Ty masz jeden punkt utrzymania dla wszystkich paczek.

## Strategia wersjonowania

- branch `main` → zawsze najnowszy (dobre dla threat-intel)
- tagi `v0.9`, `v0.9` → klient pinuje wersję, świadomie podbija (stabilność)

Threat-intel sekcje (malicious) → main + pull godzinowy.
Stabilne sekcje (providers) → tag + pull dzienny/tygodniowy.

---

## Feed update log — v0.9 (2026-07-20)

**Added 12 new entries — new frontier AI providers (H1 2026):**

| Domain | Category | Provider | Reason |
|---|---|---|---|
| chat.qwen.ai | llm-provider | Qwen (Alibaba) | Frontier open-weight model, mass adoption H1 2026 |
| dashscope.aliyuncs.com | llm-enterprise | Qwen API (Alibaba Cloud) | Enterprise API endpoint |
| kimi.com | llm-provider | Kimi (Moonshot AI) | 2M token context, competitive coding benchmarks |
| platform.moonshot.ai | llm-enterprise | Kimi API (Moonshot) | Enterprise API endpoint |
| z.ai | llm-provider | GLM (Z.ai / Zhipu) | MIT-licensed, SWE-Bench Pro leader April 2026 |
| chat.z.ai | llm-provider | GLM chat interface | Consumer chat access |
| bigmodel.cn | llm-enterprise | GLM API (Zhipu) | Enterprise API endpoint |
| minimax.chat | llm-provider | MiniMax | 1M context, competitive Chinese frontier model |
| api.minimax.chat | llm-enterprise | MiniMax API | Enterprise API endpoint |
| api.fireworks.ai | llm-enterprise | Fireworks AI | Major multi-model inference platform, previously missing |
| windsurf.com | llm-coding | Windsurf (ex-Codeium) | Codeium rebrand April 2025 |
| devin.ai | llm-coding | Devin Desktop (Cognition) | Windsurf renamed June 2026 under Cognition AI ownership |

**Naming chain note:** Codeium → Windsurf (April 2025, rebrand) → acquired by Google (team, July 2025) and Cognition AI (product) → Devin Desktop (June 2026, rename under Cognition). Legacy `codeium.com` entry retained in feed for backward compatibility with older deployments; may be deprecated in future feed versions if traffic confirms full migration.

**Total feed size: 261 entries** (was 249)
- llm-provider: 189 (+5)
- llm-enterprise: 48 (+5)
- llm-coding: 18 (+2)
- llm-malicious: 6 (unchanged)
