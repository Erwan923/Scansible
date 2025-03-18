# Trivy Scanning Techniques

* Scan Kubernetes - Résumé du cluster
        * `trivy k8s --report=summary`
        * Description: Scanner tout le cluster avec un résumé
        * Tags: #kubernetes #k8s #summary

* Scan Kubernetes - Rapport détaillé
        * `trivy k8s --report=all`
        * Description: Scanner tout le cluster avec un rapport détaillé
        * Tags: #kubernetes #k8s #detailed

* Scan Kubernetes - Namespace spécifique
        * `trivy k8s --include-namespaces [namespace] --report=summary`
        * Description: Scanner un namespace spécifique (ex: kube-system)
        * Tags: #kubernetes #namespace #specific

* Scan Kubernetes - Filtrage par sévérité
        * `trivy k8s --severity=CRITICAL --report=summary`
        * Description: Scanner avec filtrage par sévérité (ex: CRITICAL uniquement)
        * Tags: #kubernetes #severity #critical

* Scan Kubernetes - Ressource spécifique
        * `trivy k8s deployment/[deployment_name] --report=summary`
        * Description: Scanner une ressource spécifique (ex: un déploiement)
        * Tags: #kubernetes #deployment #resource

* Scan Image Docker - Basique
        * `trivy image [image_name:tag]`
        * Description: Scanner une image Docker pour les vulnérabilités
        * Tags: #docker #image #vulnerabilities

* Scan Image Docker - Filtrage par sévérité
        * `trivy image --severity=HIGH,CRITICAL [image_name:tag]`
        * Description: Scanner avec filtrage par sévérité (ex: HIGH et CRITICAL)
        * Tags: #docker #severity #filtering

* Scan Image Docker - Ignorer vulnérabilités non fixables
        * `trivy image --ignore-unfixed [image_name:tag]`
        * Description: Scanner en excluant les vulnérabilités fixables
        * Tags: #docker #ignore-unfixed #fixable

* Scan Système de Fichiers - Répertoire
        * `trivy fs [directory_path]`
        * Description: Scanner un répertoire local
        * Tags: #filesystem #directory #local

* Scan Système de Fichiers - Fichier spécifique
        * `trivy fs [file_path]`
        * Description: Scanner un fichier spécifique
        * Tags: #filesystem #file #specific

* Scan Dépôt Git
        * `trivy repo [repo_url]`
        * Description: Scanner un dépôt Git à distance
        * Tags: #git #repository #remote

* Génération Rapport JSON
        * `trivy image --format=json --output [output_file.json] [image_name:tag]`
        * Description: Générer un rapport en format JSON
        * Tags: #report #json #output

* Génération SBOM
        * `trivy image --format=spdx-json --output [sbom_file.json] [image_name:tag]`
        * Description: Générer un SBOM (Software Bill of Materials)
        * Tags: #sbom #spdx #bill-of-materials

* Installation Trivy Operator
        * `helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/ && helm install trivy-operator aquasecurity/trivy-operator --namespace trivy-system --create-namespace`
        * Description: Installer Trivy Operator via Helm dans Kubernetes
        * Tags: #operator #helm #installation

* Vérification Rapports de Vulnérabilité
        * `kubectl get vulnerabilityreports -n trivy-system`
        * Description: Vérifier les rapports de vulnérabilité générés par Trivy Operator
        * Tags: #reports #vulnerabilities #operator

* Rafraîchissement Base de Données
        * `trivy image --refresh [image_name:tag]`
        * Description: Rafraîchir les bases de données Trivy avant un scan
        * Tags: #database #refresh #update

* Scan Vulnérabilités Uniquement
        * `trivy image --security-checks vuln [image_name:tag]`
        * Description: Scanner uniquement les vulnérabilités et ignorer les mauvaises configs
        * Tags: #vulnerabilities #security-checks #vuln

* Scan Configurations Uniquement
        * `trivy k8s --security-checks config --report=summary`
        * Description: Scanner uniquement les mauvaises configurations (Kubernetes)
        * Tags: #config #misconfigurations #security-checks

* Intégration CI/CD
        * `trivy image --exit-code 1 --severity=CRITICAL [image_name:tag]`
        * Description: Exemple d'exécution Trivy dans un pipeline CI/CD avec code de sortie
        * Tags: #ci-cd #pipeline #integration