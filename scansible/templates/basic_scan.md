# Basic Scanning Techniques

* Scan standard sans Vulners
        * `nmap -sV -sC [target]`
        * Description: Détection de version et scripts par défaut
        * Tags: #version #default #discovery

* Scan Vulners basique
        * `nmap -sV --script vulners [target]`
        * Description: Scan basique des vulnérabilités
        * Tags: #vulners #cve #basic

* Scan rapide avec Vulners
        * `nmap -F --script vulners [target]`
        * Description: Scan rapide des ports les plus courants
        * Tags: #fast #vulners #quick

* Scan avec score CVSS minimum
        * `nmap -sV --script vulners --script-args mincvss=5.0 [target]`
        * Description: Filtre les vulnérabilités par score CVSS
        * Tags: #cvss #filter #critical