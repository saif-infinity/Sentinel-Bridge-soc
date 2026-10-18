# Contribuer

Merci de garder ce dépôt strictement défensif et pédagogique.

## Avant d'ouvrir une pull request

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check .
pytest
```

## Règles

- **Pas de dépendance d'exécution supplémentaire** sans justification : la
  bibliothèque standard suffit pour la génération, l'envoi HTTP et les sondes.
- **Pas de fonction offensive** : exploitation, paquets forgés, fuzzing ou
  charge applicative n'ont pas leur place ici.
- **Gardez les garde-fous** : toute nouvelle commande réseau doit passer par
  `labtools.safety`.
- **Testez** : chaque comportement ajouté doit être couvert, y compris les cas
  d'erreur et les refus de cible.
- **Documentez** : mise à jour du README et de l'aide `--help` si l'interface
  change.
- Les adresses fictives utilisent les plages RFC 5737 et les plages privées.

## Signaler un problème

Ouvrez une issue en précisant la version (`labtools --version`), la commande
exacte, la sortie observée et la sortie attendue. Ne joignez jamais de secret,
de clé API ou de donnée personnelle.
