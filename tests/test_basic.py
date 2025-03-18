import os
import sys
from pathlib import Path

# Ajouter le répertoire parent au chemin Python pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_project_structure():
    """Teste que la structure de base du projet est correcte."""
    assert os.path.exists("main.py"), "Le fichier main.py doit exister"
    assert os.path.exists("requirement.txt"), "Le fichier requirement.txt doit exister"
    assert os.path.isdir("scansible"), "Le répertoire scansible doit exister"
    assert os.path.isdir("api"), "Le répertoire api doit exister"

def test_scansible_imports():
    """Teste que les imports de base fonctionnent."""
    try:
        from scansible.core.parser import TemplateParser
        assert True
    except ImportError:
        assert False, "Impossible d'importer TemplateParser"
    
    try:
        from scansible.core.scanner import Scanner
        assert True
    except ImportError:
        assert False, "Impossible d'importer Scanner"
