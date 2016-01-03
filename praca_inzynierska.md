# Wstęp {.unnumbered}

W dzisiejszych czasach praktycznie co tydzień słyszy się w\ wiadomościach o\ wielkich wyciekach danych z\ mniej lub bardziej popularnych serwisów internetowych - dziury w bezpieczeństwie dostępu do danych odnajdywane są nawet w\ dużych serwisach, nad którymi pracują tysiące inżynierów i\ programistów. 

Istnieją dwie główne kategorie podatności aplikacji internetowej na wyciek danych:

* wadliwe zabezpieczenia struktury IT --- wykorzystywanie dziur w\ firewallach serwera, łamanie haseł do serwera głównego i\ inne techniki mogą dać włamywaczowi nieograniczony, bezpośredni dostęp do bazy danych.
* błąd w\ kodzie aplikacji internetowej --- przez nieuwagę programisty tworzącego daną aplikację zdarza się, że udostępnia użytkownikom dane, do których nie powinni mieć dostępu.

Zdarza się, że aplikacje o\ bardzo dobrze zabezpieczonej strukturze IT są podatne na wyciek danych przez błąd programistyczny. W\ dobie systemów ciągłej integracji, wiecznie rosnącego poziomu skomplikowania aplikacji internetowych i\ średniego rozmiaru zespołów programistycznych nad nimi pracujących wzrasta prawdopodobieństwo przypadkowego spowodowania wycieku danych.

W\ tej części pracy opiszę szczegółowo główne typy błędów programistów, które skutkują osłabieniem ochrony danych użytkowników, oraz sposoby, w jakie Sealious im zapobiega lub będzie zapobiegał w przyszłych wersjach.

# *Injection*

## Opis

*Injection* (ang. "wstrzyknięcie") to rodzaj ataku pozwalający atakującemu na wywołanie dowolnej kwerendy SQL (lub noSQL) na serwerze. Napisana przez atakującego kwerenda może usuwać ważne dane z\ bazy lub nadawać większe uprawnienia pewnym użytkownikom, co może doprowadzić do wycieku danych.

Podatność na *injection* występuje bardzo często - zajmuje pozycję #1 na liście najpopularniejszych podatności aplikacji webowych [zob. @owasp_top_ten, p. 7]

## Przebieg ataku

Podstawą ataku typu *injection* jest umiejętne sformułowanie niewinnie wyglądającego zapytania na serwer (np. zapytanie `HTTP POST` odpowiedzialne za logowanie lub zakładanie użytkownika) tak, aby zostały wykonane dodatkowe kwerendy, napisane przez atakującego. 

### Przykład - SQL

Rozważmy kolejne kroki ataku na przykładzie prostego systemu logowania. W celu autoryzacji loginu i\ hasła użytkownika serwer musi wykonać zapytanie do bazy danych. Załóżmy, że zapytanie SQL jest formułowane w następujący sposób:

```java
String query = "SELECT * FROM accounts WHERE username='"
     + request.getParameter("username") + "'";
```

Zakładając, że w formularzu HTML została wpisana nazwa użytkownika (zgodnie z\ przewidywaniami programisty), zapytanie przechowywane w zmiennej `query` ma postać: 

```sql
    SELECT * FROM accounts WHERE username='kuba'
```

Wynikiem takiego zapytania jest jeden wiersz bazy danych, reprezentujący użytkownika `kuba`.

Złośliwy atakujący może w formularzu HTML w\ polu `username` wpisać:

```
    ' or '1'='1
```

co sprawi, że w\ zmiennej `query` przechowywane będzie zapytanie w\ postaci:

```sql
    SELECT * FROM accounts WHERE username='' or '1'='1'
```

Takie zapytanie zamiast zwracać jednego użytkownika, zwraca całą zawartość tabeli `accounts` - co może doprowadzić do niepożądanego wycieku danych. 

### Przykład - NoSQL

Mimo, że języki NoSQL projektowane były z myślą o\ zapobieganiu atakom typu *injection*, nieuważny programista wciąż może sprawić, że aplikacja ujawni atakującemu informacje, do których ten nie powinien mieć dostępu [zob. @nosql_injection].

Rozpatrzmy prosty przykład aplikacji, która umożliwia publikowanie oraz przeglądanie postów. W tej aplikacji użytkownik ma dostęp tylko do: 

* postów jego autorstwa
* postów oznaczonych jako publiczne
* postów napisanych przez jego znajomych

Załóżmy, że kod obsługujący zapytanie o\ listę dostępnych postów zawiera następujący fragment:

```javascript
if (is_friends_with(request.params.user_id, Session.user_id) ) {
    var db_query = "{ $or : [ { public : 1 } , { owner_id : " + 
        request.params.user_id + " } ] }";
    db.posts.find(JSON.parse(db_query));
} else {
    //respond with error
}
```

Jeżeli parametr `user_id` zapytania HTTP obsługiwanego przez ten fragment kodu ma postać zgodną z przewidywaniami programisty (liczbę całkowitą - typ `Number` w\ JavaScript), zapytanie przechowywane w\ zmiennej `db_query` ma postać:

```json
{ "$or": [
        { "public": 1 },
        { "author_id": 123 }
    ]
}
```

Takie zapytanie zwróci listę postów z\ bazy danych - tylko takich, które są publiczne, lub których autorem jest zadany użytkownik

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

Takie zapytanie zwraca listę wszystkich postów z\ bazy --- zaistniał wyciek danych. 

## Zapobieganie

Podatność na ataki typu *injection* jest łatwo wykryć w\ trakcie czytania kodu --- dlatego warto dbać o to, aby każda linijka kodu odpowiedzialna za komunikację z\ bazą danych w aplikacji internetowej była przejrzana i\ zaakceptowana przez innego członka zespołu, niż jej autor. 

W przypadku SQL - warto korzystać z poleceń przygotowywanych (ang. *prepared statements*). Polecenia przygotowane są odporne na atak typu *injection*, ponieważ wymagają odseparowania struktury kwerend od danych, co uniemożliwia interpretację danych wpisanych przez użytkownika jako osobnych kwerend.

## Jak Sealious zapobiega atakom typu *injection*

Sealious reprezentuje wszystkie zapytania do bazy danych w postaci natywnego dla JavaScript obiektu (hashmapy), zgodnie ze specyfikacją interfejsu programistycznego MongoDB. Każde zapytanie MongoDB jest hashmapą - dlatego np. dla pól typu "`text`" każda wysłana przez użytkownika wartość jest wcześniej rzutowana na `String`, co uniemożliwia jej interpretację jako zapytania bazy danych. 



//broken authentication and session management

//Cross-site scripting 

//Insecure direct object reference

http://www.anandpraka.sh/

//missing function level Access Control

// Steam


// Facebook insecure direct object reference -- diagramy

# Bibliografia