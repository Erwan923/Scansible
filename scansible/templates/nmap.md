# Nmap Cheat Sheet

### Basic Scanning Techniques
* Scan standard sans Vulners
        * `nmap -sV -sC [target]`
        * Description: Détection de version et scripts par défaut
        * Tags: #version #default
* Scan Vulners basique
        * `nmap -sV --script vulners [target]`
        * Description: Scan basique des vulnérabilités
        * Tags: #vulners #cve
* Scan rapide avec Vulners
        * `nmap -F --script vulners [target]`
        * Description: Scan rapide des ports les plus courants
        * Tags: #fast #vulners
* Scan avec score CVSS minimum
        * `nmap -sV --script vulners --script-args mincvss=5.0 [target]`
        * Description: Filtre les vulnérabilités par score CVSS
        * Tags: #cvss #filter

### Advanced Scanning Options
* Scan Vulners Enterprise complet
        * `nmap -sV -sC --script vulners_enterprise,http-vulners-regex --script-args api_key=[API_KEY] [target]`
        * Description: Scan complet avec détection avancée
        * Tags: #enterprise #complete
* Scan tous ports avec Vulners
        * `nmap -p- -sV --script vulners_enterprise --script-args api_key=[API_KEY] [target]`
        * Description: Scan exhaustif de tous les ports
        * Tags: #allports #thorough
* Scan stealth avec Vulners
        * `nmap -sS -T2 --script vulners_enterprise --script-args api_key=[API_KEY] [target]`
        * Description: Scan furtif avec timing lent
        * Tags: #stealth #slow

### Web Application Scanning
* Scan WordPress
        * `nmap -sV --script http-wordpress-enum,http-wordpress-vulners [target]`
        * Description: Énumération et vulnérabilités WordPress
        * Tags: #wordpress #cms
* Scan SSL/TLS
        * `nmap -sV --script ssl-enum-ciphers,ssl-heartbleed [target]`
        * Description: Audit de la configuration SSL/TLS
        * Tags: #ssl #tls
* Scan Web Complet
        * `nmap -p80,443 -sV --script "http-*" [target]`
        * Description: Tous les scripts de test web
        * Tags: #web #http

### Infrastructure Scanning
* Scan Active Directory
        * `nmap -p88,389,636,3268,3269 --script ldap-search [target]`
        * Description: Énumération Active Directory
        * Tags: #ad #windows
* Scan Docker
        * `nmap -p2375,2376 --script docker-version,docker-api-info [target]`
        * Description: Détection et analyse Docker
        * Tags: #docker #container
* Scan Kubernetes
        * `nmap -p6443,10250 --script ssl-cert,kubernetes-api [target]`
        * Description: Audit clusters Kubernetes
        * Tags: #k8s #cloud
