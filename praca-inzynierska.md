# Wstęp {.unnumbered}

W dzisiejszych czasach praktycznie co tydzień słyszy się w wiadomościach o wielkich wyciekach danych z mniej lub bardziej popularnych serwisów internetowych---dziury w bezpieczeństwie dostępu do danych odnajdywane są nawet w dużych serwisach, nad którymi pracują tysiące inżynierów i programistów. 

Istnieją dwie główne kategorie podatności aplikacji internetowej na wyciek danych:

* **wadliwe zabezpieczenia struktury IT**---wykorzystywanie dziur w firewallach serwera, łamanie haseł do serwera głównego i inne techniki mogą dać włamywaczowi nieograniczony, bezpośredni dostęp do bazy danych.
* **błąd w kodzie aplikacji internetowej**---przez nieuwagę programisty tworzącego daną aplikację zdarza się, że udostępnia użytkownikom dane, do których nie powinni mieć dostępu.

Zdarza się, że aplikacje o bardzo dobrze zabezpieczonej strukturze IT są podatne na wyciek danych przez błąd programistyczny. W dobie systemów ciągłej integracji, wiecznie rosnącego poziomu skomplikowania aplikacji internetowych i średniego rozmiaru zespołów programistycznych nad nimi pracujących wzrasta prawdopodobieństwo przypadkowego spowodowania wycieku danych.

W tej części pracy opiszę szczegółowo główne typy błędów programistów, które skutkują osłabieniem ochrony danych użytkowników, oraz sposoby, w jakie Sealious im zapobiega lub będzie zapobiegał w przyszłych wersjach^[Należy mieć na uwadze, że Sealious jest frameworkiem do tworzenia nie tylko aplikacji internetowych---może być użyty również jako baza aplikacji *desktopowych*. Biorąc pod uwagę popularność aplikacji webowych w dzisiejszych czasach, opowiem głównie o problemach z bezpieczeństwem w Sieci.].

# *Injection*

*Injection* (ang. "wstrzyknięcie") to rodzaj ataku pozwalający atakującemu na wywołanie dowolnej kwerendy SQL (lub noSQL) na serwerze. Napisana przez atakującego kwerenda może usuwać ważne dane z bazy lub nadawać większe uprawnienia pewnym użytkownikom, co może doprowadzić do wycieku danych.

Podatność na *injection* występuje bardzo często - zajmuje pozycję #1 na liście najpopularniejszych podatności aplikacji webowych [zob. @owasp_top_ten, p. 7]

## Przebieg ataku

Podstawą ataku typu *injection* jest umiejętne sformułowanie niewinnie wyglądającego zapytania na serwer (np. zapytanie `HTTP POST` odpowiedzialne za logowanie lub zakładanie użytkownika) tak, aby zostały wykonane dodatkowe kwerendy, napisane przez atakującego. 

### Przykład - SQL

Rozważmy kolejne kroki ataku na przykładzie prostego systemu logowania. W celu autoryzacji loginu i hasła użytkownika serwer musi wykonać zapytanie do bazy danych. Załóżmy, że zapytanie SQL jest formułowane w następujący sposób:

```java
String query = "SELECT * FROM accounts WHERE username='"
     + request.getParameter("username") + "'";
```

Zakładając, że w formularzu HTML została wpisana nazwa użytkownika (zgodnie z przewidywaniami programisty), zapytanie przechowywane w zmiennej `query` ma postać: 

```sql
    SELECT * FROM accounts WHERE username='kuba'
```

Wynikiem takiego zapytania jest jeden wiersz bazy danych, reprezentujący użytkownika `kuba`.

Złośliwy atakujący może w formularzu HTML w polu `username` wpisać:

```
    ' or '1'='1
```

co sprawi, że w zmiennej `query` przechowywane będzie zapytanie w postaci:

```sql
    SELECT * FROM accounts WHERE username='' or '1'='1'
```

Takie zapytanie zamiast zwracać dane jednego użytkownika, zwraca całą zawartość tabeli `accounts` - co może doprowadzić do niepożądanego wycieku danych. 

### Przykład - NoSQL

Mimo, że języki NoSQL projektowane były z myślą o zapobieganiu atakom typu *injection* [@nosql_prevents_injection], nieuważny programista wciąż może sprawić, że aplikacja ujawni atakującemu informacje, do których ten nie powinien mieć dostępu [zob. @nosql_injection].

Rozpatrzmy prosty przykład aplikacji, która umożliwia publikowanie oraz przeglądanie postów. W tej aplikacji użytkownik ma dostęp tylko do: 

* postów jego autorstwa
* postów oznaczonych jako publiczne
* postów napisanych przez jego znajomych

Załóżmy, że kod obsługujący zapytanie o listę dostępnych postów zawiera następujący fragment:

```javascript
if (is_friends_with(request.params.user_id, Session.user_id) ) {
    var db_query = "{ $or : [ { public : 1 } , { owner_id : " + 
        request.params.user_id + " } ] }";
    db.posts.find(JSON.parse(db_query));
} else {
    //respond with error
}
```

Jeżeli parametr `user_id` zapytania HTTP obsługiwanego przez ten fragment kodu ma postać zgodną z przewidywaniami programisty (liczbę całkowitą - typ `Number` w JavaScript), zapytanie przechowywane w zmiennej `db_query` ma postać:

```json
{ "$or": [
        { "public": 1 },
        { "author_id": 123 }
    ]
}
```

Takie zapytanie zwróci listę postów z bazy danych - tylko takich, które są publiczne, lub których autorem jest zadany użytkownik

Jeżeli złośliwy atakujący podałby jako wartość parametru `owner_id` ciąg znaków: 

```
123 }, { public: 0
```

to zapytanie przechowywane w zmiennej `db_query` ma postać:

```json
{ "$or": [
        { "public": 1 },
        { "owner_id": 123 },
        { "public": 0}
    ]
}
```

Takie zapytanie zwraca listę wszystkich postów z bazy---zaistniał wyciek danych. 

## Zapobieganie

Podatność na ataki typu *injection* jest łatwo wykryć w trakcie czytania kodu---dlatego warto dbać o to, aby każda linijka kodu odpowiedzialna za komunikację z bazą danych w aplikacji internetowej była przejrzana i zaakceptowana przez innego członka zespołu, niż jej autor. 

W przypadku SQL - warto korzystać z poleceń przygotowywanych (ang. *prepared statements*). Polecenia przygotowane są odporne na atak typu *injection*, ponieważ wymagają odseparowania struktury kwerend od danych, co uniemożliwia interpretację danych wpisanych przez użytkownika jako osobnych kwerend.

W przypadku noSQL w dużej mierze wystarczy pilnować, aby kwerenda zawsze była przechowywana w postaci hashmapy, a nie ciągu znaków.

## Przykłady ataku typu *injection* w dużych aplikacjach

Mimo, że o podatności na ataki typu *injection* traktuje bardzo wiele kursów o bezpieczeństwie aplikacji internetowych^[potrzebne cytaty], to wciąż notorycznie słyszy się o poważnych w skutkach atakach osiągniętych przez wykorzystywanie właśnie tej dziury w zabezpieczeniach:

* słynny atak LulzSec na sieć PlayStation Network - w wyniku którego atakujący zyskali pełen dostęp do bazy danych i kodu źródłowego serwisu [@lulz_sec_sony]
* w 2009 roku pewien Amerykanin wykradł dane kart kredytowych 130 milionów obywateli za pomocą *SQL injection* [@130m_cards]

## Jak Sealious zapobiega atakom typu *injection*

Sealious reprezentuje wszystkie zapytania do bazy danych w postaci natywnego dla JavaScript obiektu (hashmapy), zgodnych ze specyfikacją interfejsu programistycznego MongoDB. Każde zapytanie MongoDB jest hashmapą - dlatego np. dla pól typu "`text`" każda wysłana przez użytkownika *wartość pola* jest wcześniej rzutowana na `String`. Takie podejście uniemożliwia zajście sytuacji opisanej powyżej. Takie rzutowanie na typ `String` możemy zaobserwować w poniższym fragmencie kodu^[kod pochodzi z pliku `lib/base-chips/field_type.text.js`, w kodzie źródłowym Sealiousa z wersji `0.6.21`]:

```javascript
if (value_in_code instanceof Object) {
    return Promise.resolve(JSON.stringify(value_in_code));
} else if (value_in_code === null) {
    return Promise.resolve(null);
} else {
    return Promise.resolve(value_in_code.toString());
}
```

Dodatkowo, Sealious jest napisany w taki sposób, że docelowy deweloper tworzący aplikację przy jego użyciu nie musi własnoręcznie formułować kwerend do bazy danych - co eliminuje ryzyko przypadkowego uczynienia tej aplikacji podatną na noSQL injection.




# Błędy w autentykacji i zarządzaniu sesją

W trakcie tworzenia aplikacji deweloperzy często ulegają pokusie stworzenia własnego procesu autentykacji użytkownika. Nie jest to łatwe zadanie, dlatego potencjalnie taka aplikacja jest podatna na ataki, w których złośliwy agent podszywa się pod uprzywilejowanego użytkownika.

## Przebieg ataku

### Ujawnienie id sesji

Należy pamiętać, że id sesji jednoznacznie identyfikuje użytkownika i trzeba dbać o to, aby nie zostało ono ujawnione. Rozpatrzmy przebieg ataku na przykładzie hipotetycznej sieci społecznościowej.

1. Użytkownik A loguje się do interfejsu webowego pewnej sieci społecznościowej.

2. Użytkownik A znalazł opublikowane przez kogoś na tym serwisie bardzo śmieszne zdjęcie kota.
 
3. Widoczny w pasku adresu przeglądarki URL zawiera identyfikator sesji użytkownika: 
   
    http://example.com/pics/7553?**jsessionid=9cdfb439c7876e**
 
4. Użytkownik A zechciał podzielić się radością płynącą z tego zdjęcia ze swoim znajomym, użytkownikiem B, więc skopiował URL z paska adresu i wkleił go do treści wiadomości email, po czym wysłał ją.
 
5. Użytkownik B wiadomości otwiera zawarty w tej wiadomości link.
 
6. Serwer odbiera zapytanie wywołane przez otwarcie przez użytkownika B tego linku, wczytuje id sesji z URL i rozpoznaje w nim użytkownika A.
 
7. Użytkownik B jest zalogowany do sieci społecznościowej jako użytkownik A.

### Wyciek haseł
 
Osoba mająca fizyczny dostęp do bazy danych danej aplikacji (lub zdalny dostęp, za pomocą ataku typu *injection*) może wczytać zawartość tabeli przechowującej dane logowania użytkowników. 

Jeżeli hasła te są przechowywane w postaci jawnego tekstu, atakujący może od razu użyć ich, aby zalogować się jako dowolny użytkownik z pozyskanej tabeli.

## Zapobieganie

### Zapobieganie ujawnieniu id sesji

Id sesji powinno być traktowane jako sekret. Podjęcie następujących kroków zdecydowanie utrudnia atakującemu jego przechwycenie:

* **wymuszenie korzystania z protokołu `HTTPS` do wszystkich zapytań związanych z obsługą sesji**

    Dane wysyłane za pośrednictwem protokołu `HTTPS` są szyfrowane, co utrudnia (ale nie uniemożliwia[^ssl_breakable_footnotes]) ich przechwycenia.

[^ssl_breakable_footnotes]: Odpowiednio zainfekowane maszyny są w stanie umożliwić ataki typu Man-In-The-Middle nawet dla połączeń HTTPS [zob. @superfish_ssl]

* **przechowywanie identyfikatora sesji w pliku cookie zamiast w URL**
    
    Jest to bardzo skuteczny sposób zabezpieczenia użytkownika przed przypadkowym samodzielnym zdradzeniem komuś swojego identyfikatora sesji. Raz zapisana w pliku cookie wartość jest automatycznie dołączana przez przeglądarkę internetową do każdego zapytania kierowanego do danej aplikacji, co znosi też z programisty obowiązek upewniania się, że w zapytaniu nie brakuje owego id.
    


### Zapobieganie wyciekaniu haseł

Aby zapobiec wyciekom haseł, można je przechowywać w bazie danych wartości pewnej funkcji hashującej każdego hasła, zamiast haseł w postaci jawnego tekstu. Wtedy przy próbie logowania wystarczy porównać wartość tej funkcji dla podanego przez użytkownika hasła z wartością przechowywaną w bazie.

Często^[zob. https://github.com/search?q=md5%28password%29&type=Code] używaną funkcją haszującą hasła jest `md5` - mimo, że nie jest to funkcja odporna na kolizje [^md5_bad_przypisy]. Organizacja *Internet Engineering Task Force* zaleca korzystania z algorytmu `PBKDF2` [zob. @pbkdf2_recommended]

[^md5_bad_przypisy]: [@md5_not_suitable_ms], [@md5_not_suitable]

Niestety jeżeli atakujący zyska dostęp do zahaszowanych haseł, może użyć ogólnie dostępnych [@rainbow_tables] tablic wartości danej funkcji haszującej do błyskawicznego odgadnięcia haseł (tzw. *rainbow tables*).

Można się przed tym zabezpieczyć używając tzw. "solenia" (ang. *salting*). Proces ten polega na wstępnej modyfikacji tekstu przed obliczeniem dla niego wartości funkcji haszującej^[potrzebny cytat z książki o kryptografii], co utrudnia wykorzystywanie *rainbow tables* do łamania haseł.

## Zarządzanie sesją w Sealiousie[^channel_responsibility_footnote]

### Bezpieczeństwo identyfikatora sesji

[^channel_responsibility_footnote]: Sealious w obecnej odsłonie (wersja `0.6.21-stable` i wersja `0.7-alpha`, stan ze stycznia 2016) nie zawiera mechanizmu sesji - aktualna struktura naszego frameworka wymaga, aby to chipy typu *channel* implementowały swój mechanizm weryfikacji identyfikatora sesji. Części tej sekcji odnoszące się do protokołów `http`(`s`) i plików *cookies* tyczą się konkretnego pluginu do Sealiousa - `sealious-www-server`.

`sealious-www-server`, plugin pozwalający na komunikację z aplikacją Sealiousową za pomocą protokołów `HTTP` i `HTTPS`, ułatwia konfigurację szyfrowania SLL---wystarczy tylko podać adresy portów:

```javascript
Sealious.ConfigManager.set_config(
    "chip.channel.www_server", {
        connections: {
            https: {
                port: 4430,
                tls: {
                    key: fs.readFileSync("sealious.key"),
                    cert: fs.readFileSync("sealious.crt")
                }
            }
        }
    }
)
```

`sealious-www-server` nie może domyślnie włączać `HTTPS`, gdyż wymagany do działania tego protokołu jest podpisany certyfikat `TLS`---stąd potrzeba ręcznej konfiguracji.

Po udanym zalogowaniu identyfikator sesji jest generowany losowo i haszowany za pomocą algorytmu sha1^[poniższy przykład kodu pochodzi z pliku `define/channel.www_server.js` z repozytorium `Sealious/sealious-www-server`]:

```javascript
function generate_session_id() {
    var seed = Math.random().toString();
    var session_id = sha1(seed);
    return session_id;
}
```

Następnie wpisywany jest do nagłówka odpowiedzi HTTP instruującego przeglądarkę do utworzenia nowego wpisu w pliku cookie:

```javascript
if(request.payload.redirect_success){
    reply()
        .state('SealiousSession', session_id)
        .redirect(request.payload.redirect_success);
}else{
    reply("http_session: Logged in!")
        .state('SealiousSession', session_id);
}
```

### Bezpieczeństwo haseł użytkowników

Pole `password` w zasobie typu `user` w Sealiousie jest obsługiwane przez `field_type.hashed_text`. Ten typ pola generuje hash hasła użytkownika używając zalecanego przez organizację *Internet Engineering Task Force* [zob. @pbkdf2_recommended] algorytmu `PBKDF2`:

```javascript
encode: function(context, params, value_in_code){
    var salt = "", algorithm = "md5";
    if (params) {
        if (params.salt) {
            salt = params.salt;
        }
        else if (params.algorithm) {
            algorithm = params.algorithm;
        }
    }
    return new Promise(function(resolve, reject){
        crypto.pbkdf2(
            value_in_code, salt, 
            4096, 64, algorithm, 
            function(err, key){
                err ? reject(err) : resolve(key.toString('hex'));
            }
        );
    })
}
```

Zabezpiecza to hasła użytkowników przed złamaniem w wypadku wycieku informacji z bazy danych.

//Cross-site scripting 

//Insecure direct object reference

http://www.anandpraka.sh/

//missing function level Access Control

// Steam


// Facebook insecure direct object reference -- diagramy

# Bibliografia