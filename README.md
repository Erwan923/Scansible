# <div align="center"><img src="assets/images/noun-anime-5257669.svg" width="60" valign="bottom"/> SCANSIBLE</div>

<div align="center">
  <strong>Automatisation de scans de sécurité avec Ansible</strong><br>
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg"/>
  <img src="https://img.shields.io/badge/license-MIT-green.svg"/>

Scansible automatise les scans de sécurité en orchestrant des outils de scans de vulnérabilités via Ansible, avec génération de rapports intelligents.

## Installation
```bash
git clone https://github.com/Erwan923/Scansible.git
cd Scansible
pip install -r requirement.txt
```

## Utilisation

### Scans Rapides
```bash
# Scan basique
python main.py 192.168.1.100

# Scan web
python main.py example.com --type web

# Scan avec tags
python main.py 192.168.1.100 --tags ssl http
```

### Types de Scans
- `basic` - Scan Nmap standard
- `web` - Vulnérabilités web
- `passive` - Reconnaissance sans interaction
- `infrastructure` - Analyse complète
- `rustscan` - Scan rapide (RustScan)
- `trivy` - Analyse de conteneurs
- `light` - Scan léger

### Options Principales
```bash
python main.py --help              # Afficher l'aide
python main.py --list-tags         # Lister les tags disponibles
python main.py <target> --ai-report # Générer un rapport IA
python main.py --gui               # Lancer l'interface web
```

## Rapports
Les résultats sont disponibles en XML, JSON, Markdown et HTML avec une analyse IA optionnelle.

## Architecture
```
├── API REST (FastAPI)
├── Core (Parser, Scanner)
├── Rapports (XML/JSON/MD/HTML)
└── Templates de Scan (Markdown)
```

## Contribution
Les contributions sont les bienvenues. Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour plus d'informations.

## Licence
MIT
