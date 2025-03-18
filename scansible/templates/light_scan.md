# Scans Légers et Rapides

Ce document contient une collection de commandes de scan légères et rapides, idéales pour des tests initiaux ou des environnements où les scans intensifs ne sont pas appropriés.

## Commandes Nmap Légères

* Scan TCP Connect rapide des ports courants
* `nmap -sT -T4 -p 80,443,22,21,25,3306,8080 [target]`
* Description: Scan Connect rapide des ports les plus courants
* Tags: #fast #tcp #connect #common-ports

* Scan de version basique
* `nmap -sV --version-light -T4 -p 80,443,22 [target]`
* Description: Détection de version légère sur les ports les plus critiques
* Tags: #fast #version #service-detection

* Scan de réseau rapide
* `nmap -sn -T4 [target]`
* Description: Ping scan rapide pour découvrir les hôtes actifs sans scan de port
* Tags: #fast #discovery #ping

* Scan HTTP basique
* `nmap -p 80,443 --script=http-title,http-headers [target]`
* Description: Scan basique des services web avec scripts minimaux
* Tags: #fast #web #http

## Commandes RustScan Rapides

* Scan RustScan minimal
* `rustscan -a [target] --ulimit 5000`
* Description: Scan rapide avec une limite de 5000 ports ouverts
* Tags: #fast #rustscan #minimal

* Scan RustScan avec plage de ports limitée
* `rustscan -a [target] --range 1-1000`
* Description: Scan uniquement les 1000 premiers ports
* Tags: #fast #rustscan #limited-range

* Scan RustScan de ports spécifiques
* `rustscan -a [target] -p 22,80,443,3306,8080`
* Description: Scan ciblé uniquement sur les ports spécifiés
* Tags: #fast #rustscan #specific-ports

* Scan RustScan avec timeout court
* `rustscan -a [target] --timeout 1000`
* Description: Scan avec timeout court pour une exécution plus rapide
* Tags: #fast #rustscan #quick