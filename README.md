# Scansible - Outil d'automatisation de scans de sécurité

<p align="center">
  <img src="https://via.placeholder.com/200x200.png?text=SCANSIBLE" width="200" />
</p>

## Description
Scansible est un outil puissant qui automatise les scans de sécurité avec Nmap, RustScan et Trivy via Ansible. Il simplifie l’évaluation des vulnérabilités avec une interface claire et des rapports détaillés.

## Fonctionnalités
- 🔍 **Multiples types de scans** : rapide, web, infra, passif...
- 📊 **Rapports HTML interactifs** avec IA
- 🚀 **Interface CLI intuitive**
- 🏷️ **Filtrage des vulnérabilités par tags**

## Installation
### Prérequis
- Python 3.8+
- Nmap, RustScan ou Trivy
- Ansible

### Installation
```bash
git clone https://github.com/Erwan923/Scansible.git
cd Scansible
pip install -r requirements.txt


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
Pour chaque.md le user peux ajouté ses propre tools
