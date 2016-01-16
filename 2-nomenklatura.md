# Nomenklatura frameworka Sealious {-}

Struktura Sealiousa nie była bezpośrednio inspirowana żadnym dotychczas istniejącym frameworkiem, przez co nazwy niektórych struktur w nim się znajdujących posiadają oryginalne, określone przez nas nazwy. Ich znaczenia i wzajemne relacje są dokładniej wytłumaczone w pracy opisującej część pierwszą naszego tematu^[Praca inżynierska Poli Mikołajczak, pt. *Rozwój open-source’owego frameworka do tworzenia aplikacji - ”Sealious” (cz. 1)*. Realizowana na WMI UAM pod opieką prof. Marka Nawrockiego], ale dla wygody Czytelnika po krótce opiszę najważniejsze z nich:

* *chip* - zbiór funkcjonalności realizujący określone zadanie w aplikacji tworzonej za pomocą Sealiousa. 
* *deklaratywny opis aplikacji* - zbiór deklaracji funkcjonalności aplikacji napisany wg. określonych schematów. Nie zawiera *imperatywnych* instrukcji---tylko informacje o tym, *co* aplikacja ma robić, ale nie *jak*.
* *aplikacja sealiousowa* - aplikacja tworzona za pomocą Sealiousa. Jej funkcjonalność jest jednoznacznie zdefiniowana jest przez jej deklaratywny opis oraz zbiór chipów.
* *resource (zasób)* - rekord w bazie danych. Ma określoną strukturę i prawa dostępu.
* *context (kontekst)* - obiekt. Zawiera informacje nt. kontekstu, w jakim zostało wykonane zapytanie do aplikacji sealiousowej (id użytkownika, timestamp, adres IP klienta). 
* *chip type (typ chipu)* - zbiór wymagań odnośnie funkcjonowania i przeznaczenia chipu. W wersji `0.6` Sealiousa zdefiniowane są następujące typy:
    - *channel (kanał)* - umożliwia komunikację z aplikacją sealiousową za pomocą jakiegoś protokołu
    - *resource type (typ zasobu)* - opis struktury zasobu
    - *field type (typ pola zasobu)* - opis pola struktury zasobu. Zawiera informacje o walidacji i sposobie przechowywania wartości w bazie danych.
    - *access strategy (strategia dostępu)* - opis logiki przydzielania dostępu na podstawie zadanego kontekstu



