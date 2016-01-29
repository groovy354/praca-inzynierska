# Cel i zakres pracy {-}

W dzisiejszych czasach praktycznie co tydzień słyszy się w wiadomościach o wielkich wyciekach danych z mniej lub bardziej popularnych serwisów internetowych---dziury w bezpieczeństwie dostępu do danych odnajdywane są nawet w dużych serwisach, nad którymi pracują tysiące inżynierów i programistów. 

Zdarza się, że aplikacje o bardzo dobrze zabezpieczonej strukturze IT są podatne na wyciek danych przez błąd programistyczny. W dobie systemów ciągłej integracji, wiecznie rosnącego poziomu skomplikowania aplikacji internetowych i średniego rozmiaru zespołów programistycznych nad nimi pracujących wzrasta prawdopodobieństwo przypadkowego spowodowania wycieku danych.

Wyłaniają się dwie główne kategorie źródeł podatności aplikacji internetowej na wyciek danych:

* **wadliwe zabezpieczenia struktury IT**---wykorzystywanie dziur w firewallach serwera, łamanie haseł do serwera głównego i inne techniki mogą dać włamywaczowi nieograniczony, bezpośredni dostęp do bazy danych.
* **błąd w kodzie aplikacji internetowej**---przez nieuwagę programisty tworzącego daną aplikację zdarza się, że udostępnia użytkownikom dane, do których nie powinni mieć dostępu.

W niniejszej pracy skupię się na drugiej kategorii: błędach programistów, które skutkują osłabieniem ochrony danych użytkowników---ponieważ są to problemy, którym framework programistyczny (w tym przypadku Sealious) jest w stanie zapobiec.  Omówię sposoby, w jakie Sealious tym problemom przeciwdziała lub będzie przeciwdziałał w przyszłych wersjach^[Należy mieć na uwadze, że Sealious jest frameworkiem do tworzenia nie tylko aplikacji internetowych---może być użyty również jako baza aplikacji *desktopowych*. Biorąc pod uwagę popularność aplikacji webowych w dzisiejszych czasach, opowiem głównie o problemach z bezpieczeństwem w Sieci.].


