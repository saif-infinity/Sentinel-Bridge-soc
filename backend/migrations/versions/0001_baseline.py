"""Baseline du schéma existant.

Révision : 0001
Créée à partir de : aucun état antérieur

Les déploiements actuels obtiennent leur schéma via `Base.metadata.create_all()`
au démarrage. Cette révision sert de point d'ancrage :

* sur une base **existante**, ne rien exécuter — faire `alembic stamp head` ;
* sur une base **neuve**, `alembic upgrade head` recrée exactement ce que
  `create_all()` produisait.

`upgrade()` délègue volontairement à `Base.metadata.create_all` plutôt que de
duplicater 46 `op.create_table(...)` à la main : la seconde copie divergerait
des modèles dès le premier ajout de colonne. À partir d'ici, toute évolution de
schéma passe par `alembic revision --autogenerate`.
"""
from alembic import op

from app.db import Base
from app.domain import (
    investigations,  # noqa: F401
    models,  # noqa: F401
)

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
