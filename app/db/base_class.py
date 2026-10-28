from sqlalchemy.orm import DeclarativeBase, declared_attr


class Base(DeclarativeBase):
    """
    Clase base declarativa para todos los modelos de SQLAlchemy 2.0.
    Genera automáticamente el __tablename__ basado en el nombre de la clase si no se define.
    """

    @declared_attr.directive
    def __tablename__(cls) -> str:
        return cls.__name__.lower()
