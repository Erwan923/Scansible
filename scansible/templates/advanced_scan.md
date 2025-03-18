# Advanced Scanning Techniques

* Scan Vulners Enterprise complet
        * `nmap -sV -sC --script vulners_enterprise,http-vulners-regex --script-args api_key=[API_KEY] [target]`
        * Description: Scan complet avec détection avancée des vulnérabilités
        * Tags: #enterprise #complete #thorough
* Scan tous ports avec Vulners
        * `nmap -p- -sV --script vulners_enterprise --script-args api_key=[API_KEY] [target]`
        * Description: Scan exhaustif de tous les ports avec analyse des vulnérabilités
        * Tags: #allports #thorough #comprehensive
* Scan stealth avec Vulners
        * `nmap -sS -T2 --script vulners_enterprise --script-args api_key=[API_KEY] [target]`
        * Description: Scan furtif avec timing lent pour éviter la détection
        * Tags: #stealth #slow #evasion
* Scan UDP avancé
        * `nmap -sU -sV --version-intensity 5 --script vulners_enterprise --script-args api_key=[API_KEY] [target]`
        * Description: Scan approfondi des services UDP
        * Tags: #udp #services #advanced