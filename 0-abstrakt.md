# Abstrakt (j. polski) {-}

W dzisiejszych czasach aplikacje internetowe stanowią bardzo ważny aspekt życia profesjonalnego i prywatnego każdego z nas---dlatego dbanie, aby programy nie udostępniały danych nieupoważnionym podmiotom jest bardzo ważne. Mimo powszechnej świadomości o (przynajmniej niektórych z) możliwych podatności aplikacji na ataki wśród programistów, nieustannie dowiadujemy się o wyciekach danych z wielkich sieci społecznościowych, sklepów, a nawet banków.

Dobry framework powinien skutecznie przeciwdziałać powstawaniu dziur bezpieczeństwa aplikacji w nich tworzonych. W niniejszej pracy opiszę, jak deklaratywny framework Sealious zapobiega popularnym podatnościom na ataki napisanych przy jego pomocy programów działających w Sieci, a w szczególności: 

* Injection
* Insecure Direct Object Reference
* Błędy w iplementacji uwierzytelniania 
* Cross-Site Scripting (XSS)

# Abstract (in English) {-}

In today's world a modern person's professional and personal lifes are strongly affected by various Internet-powered appliactions. Event though making those applications resistant to data leaks and attacks is a high priority for their developers, often small oversights lead to severe vulnerabilities. Such vulnerabilities are repeatedly found in social networks, e-shops, and event e-banks.

A good framework should guard applications written in it from such vulnerabilities---and that's exactly one of the things that Sealious, a declarative framework for Node.js, aims to achieve. In this thesis I'll explore the various ways in which Sealious prevents, amongst others: 

* Injections
* Insecure Direct Object References
* Broken Authentication and Session Management
* Cross-Site Scripting attacks


