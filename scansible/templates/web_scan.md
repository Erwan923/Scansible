# Web Application Scanning

* Scan WordPress détaillé
        * `nmap -sV --script http-wordpress-enum,http-wordpress-vulners [target]`
        * Description: Énumération et détection des vulnérabilités WordPress
        * Tags: #wordpress #cms #web
* Scan SSL/TLS approfondi
        * `nmap -sV --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params [target]`
        * Description: Audit complet de la configuration SSL/TLS et vulnérabilités connues
        * Tags: #ssl #tls #crypto
* Scan Web Complet
        * `nmap -p80,443 -sV --script "http-*" [target]`
        * Description: Exécution de tous les scripts de test web disponibles
        * Tags: #web #http #comprehensive
* Scan Drupal
        * `nmap -p80,443 -sV --script http-drupal-enum,http-drupal-modules [target]`
        * Description: Énumération Drupal et recherche de modules vulnérables
        * Tags: #drupal #cms #web
* Scan Joomla
        * `nmap -p80,443 -sV --script http-joomla-brute,http-joomla-enum [target]`
        * Description: Tests de sécurité spécifiques à Joomla
        * Tags: #joomla #cms #web
* Scan Applications Web Génériques
        * `nmap -p80,443 -sV --script http-enum,http-headers,http-methods,http-auth [target]`
        * Description: Découverte et analyse des applications web génériques
        * Tags: #webapp #discovery #enum