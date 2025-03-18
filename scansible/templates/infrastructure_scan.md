# Infrastructure Scanning

* Scan Active Directory
        * `nmap -p88,389,636,3268,3269 --script ldap-search,ldap-rootdse [target]`
        * Description: Énumération Active Directory et services LDAP
        * Tags: #ad #windows #ldap
* Scan Docker
        * `nmap -p2375,2376 --script docker-version,docker-api-info,docker-containers [target]`
        * Description: Détection et analyse des services Docker
        * Tags: #docker #container #devops
* Scan Kubernetes
        * `nmap -p6443,10250,10255,10256 --script ssl-cert,kubernetes-api [target]`
        * Description: Audit des clusters Kubernetes et API exposées
        * Tags: #k8s #cloud #container
* Scan Cloud Services
        * `nmap -p80,443,8080 --script http-cloud-services,http-aws-services [target]`
        * Description: Détection des services cloud (AWS, Azure, GCP)
        * Tags: #cloud #aws #azure
* Scan Base de données
        * `nmap -p1433,1521,3306,5432 --script ms-sql-info,mysql-info,pgsql-brute [target]`
        * Description: Analyse des bases de données exposées
        * Tags: #database #sql #storage
* Scan Virtualisation
        * `nmap -p902,903,5900,5901 --script vmware-version,citrix-enum-servers [target]`
        * Description: Détection des plateformes de virtualisation
        * Tags: #vmware #citrix #virtual
* Scan IoT
        * `nmap -p80,443,1883,8883 --script mqtt-subscribe,coap-version [target]`
        * Description: Découverte des dispositifs et protocoles IoT
        * Tags: #iot #mqtt #coap