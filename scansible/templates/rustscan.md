# RustScan Scanning Techniques

* Scan rapide de tous les ports TCP
        * `rustscan -a [target]`
        * Description: Scan ultra-rapide de tous les ports TCP
        * Tags: #fast #discovery #all-ports

* Scan avec limite de fichiers augmentée
        * `rustscan -a [target] --ulimit 5000`
        * Description: Scan accéléré avec limite de fichiers augmentée
        * Tags: #fast #performance #ulimit

* Scan de ports spécifiques
        * `rustscan -a [target] -p 22,80,443`
        * Description: Scan ciblé sur des ports spécifiques
        * Tags: #targeted #specific #ports

* Scan d'une plage de ports
        * `rustscan -a [target] --range 1-1000`
        * Description: Scan d'une plage de ports définie
        * Tags: #range #ports #limited

* Scan avec options Nmap basiques
        * `rustscan -a [target] -- -sV -sC`
        * Description: Scan rapide suivi d'une analyse Nmap détaillée
        * Tags: #nmap #version #scripts

* Scan avec options Nmap avancées
        * `rustscan -a [target] -- -A`
        * Description: Scan rapide suivi d'une analyse Nmap complète
        * Tags: #nmap #advanced #complete

* Scan avec ordre aléatoire des ports
        * `rustscan -a [target] --range 1-1000 --scan-order "Random"`
        * Description: Scan avec ordre aléatoire pour éviter la détection
        * Tags: #evasion #random #stealth

