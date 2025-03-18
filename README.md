# Scansible - Outil d'automatisation de scans de sécurité


⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣴⣶⣶⣶⣶⣦⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⠏⠁⠀⢶⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀
⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⡿⠿⣿⠀⠀⠀⠀⣿⠿⢿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀
⠀⢠⣾⣿⣿⣿⣿⣿⡿⠋⣠⣴⣿⣷⣤⣤⣾⣿⣦⣄⠙⢿⣿⣿⣿⣿⣿⣷⡄⠀
⠀⣼⣿⣿⣿⣿⣿⡏⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⢹⣿⣿⣿⣿⣿⣧⠀
⢰⣿⣿⣿⣿⣿⡿⠀⣾⣿⣿⣿⣿⠟⠉⠉⠻⣿⣿⣿⣿⣷⠀⢿⣿⣿⣿⣿⣿⡆
⢸⣿⣿⣿⣿⣿⣇⣰⣿⣿⣿⣿⡇⠀⠀⠀⠀⢸⣿⣿⣿⣿⣆⣸⣿⣿⣿⣿⣿⡇
⠸⣿⣿⣿⡿⣿⠟⠋⠙⠻⣿⣿⣿⣦⣀⣀⣴⣿⣿⣿⣿⠛⠙⠻⣿⣿⣿⣿⣿⠇
⠀⢻⣿⣿⣧⠉⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠈⣿⣿⣿⡟⠀
⠀⠘⢿⣿⣿⣷⣦⣤⣴⣾⠛⠻⢿⣿⣿⣿⣿⡿⠟⠋⣿⣦⣤⠀⣰⣿⣿⡿⠃⠀
⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣄⣈⣁⣠⣤⣶⣾⣿⣿⣷⣾⣿⣿⡿⠁⠀⠀
⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠻⠿⠿⠿⠿⠟⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀

<img align="right" width="200" src="https://via.placeholder.com/200x200.png?text=SCANSIBLE">

## Description

Scansible est un outil puissant qui automatise les scans de sécurité en combinant différents outils comme Nmap, RustScan et Trivy via Ansible. Il simplifie le processus d'évaluation de la sécurité de vos systèmes en fournissant une interface uniforme et des rapports détaillés.

## Fonctionnalités

- 🔍 **Multiples types de scans** adaptés à différents besoins
- 🚀 **Interface en ligne de commande simple**
- 📊 **Rapports HTML interactifs** avec visualisations
- 🤖 **Génération automatique de rapports** avec IA
- 🏷️ **Filtrage par tags** pour cibler des vulnérabilités spécifiques
- 📂 **Organisation automatique des résultats** dans une structure claire

## Installation

### Prérequis

- Python 3.8+
- Nmap, RustScan ou Trivy (au moins un)
- Ansible

### Installation

```bash
# Cloner le dépôt
git clone https://github.com/yourusername/scansible.git
cd scansible

# Installer les dépendances
pip install -r requirements.txt
```

## Utilisation

### Scan basique

```bash
python main.py 192.168.1.1
```

### Types de scans disponibles

```bash
# Scan léger (rapide)
python main.py 192.168.1.1 --type light

# Scan web (applications)
python main.py example.com --type web

# Scan d'infrastructure
python main.py 192.168.1.1 --type infrastructure

# Scan passif
python main.py 192.168.1.1 --type passive

# Scan avec RustScan
python main.py 192.168.1.1 --type rustscan

# Scan avec Trivy (conteneurs)
python main.py alpine:latest --type trivy
```

### Filtrage par tags

```bash
# Scan ciblant uniquement les services HTTP et SSL
python main.py example.com --tags http ssl
```

### Génération de rapports IA

```bash
# Générer automatiquement un rapport IA
python main.py 192.168.1.1 --ai-report
```

### Lister les tags disponibles

```bash
python main.py --list-tags
```

## Types de scans

| Type | Description | Utilisation |
|------|-------------|------------|
| `basic` | Scan standard avec énumération de services | Usage général |
| `light` | Scan rapide des ports et services principaux | Vérifications rapides |
| `web` | Détection de vulnérabilités d'applications web | Sites web, API |
| `infrastructure` | Analyse approfondie de l'infrastructure | Serveurs, réseaux |
| `passive` | Reconnaissance sans contact direct | Collecte d'informations |
| `rustscan` | Scan ultra-rapide avec RustScan | Grandes plages d'IP |
| `trivy` | Analyse de conteneurs et applications | Images Docker |

## Structure des rapports

Les rapports sont automatiquement organisés dans les répertoires suivants :

- `reports/html_reports/` - Rapports HTML interactifs
- `reports/markdown_reports/` - Rapports en format Markdown
- `reports/json_reports/` - Résultats bruts au format JSON
- `reports/xml_reports/` - Résultats bruts au format XML

## Personnalisation

### Templates de scan

Les templates de scan sont définis dans des fichiers markdown dans le répertoire `scansible/templates/`. Vous pouvez les modifier ou en ajouter de nouveaux pour personnaliser les scans.

Format des templates :
```markdown
# Nom du scan

## Nom de la commande
* Description de la commande
* `nmap -sS -p 1-1000 [target]`
* Description: Description détaillée
* Tags: #tag1 #tag2 #tag3
```

## Exemples de cas d'utilisation

1. **Audit de sécurité hebdomadaire**
   ```bash
   python main.py 192.168.1.0/24 --type basic --ai-report
   ```

2. **Vérification rapide d'un serveur web**
   ```bash
   python main.py example.com --type web --tags http ssl
   ```

3. **Analyse d'une image Docker**
   ```bash
   python main.py nginx:latest --type trivy
   ```

## Dépannage

### Problèmes courants

- **Aucun outil de scan n'est disponible** : Installez au moins un des outils suivants : Nmap, RustScan ou Trivy
- **Erreur de permission** : Certains types de scans nécessitent des privilèges élevés, utilisez `sudo`
- **Rapport incomplet** : Vérifiez que les dépendances pour la génération de rapports sont installées

## Licence

Ce projet est sous licence MIT.

## Développé par

[Votre nom] - [Votre site web/GitHub]

---

*Note: Le frontend web et les fonctionnalités Docker sont en cours de développement.*
