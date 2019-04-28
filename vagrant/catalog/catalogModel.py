from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'useinfo'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

class Catalog(Base):
        __tablename__ = 'catalog'

        id = Column(Integer, primary_key=True)
        name = Column(String(250), nullable=False)
        user_id = Column(Integer, ForeignKey('useinfo.id'))
        user = relationship(User)

        @property
        def serialize(self):
            """Return object data in easily serializeable format"""
            return {
                'name': self.name,
                'id': self.id,
            }

class CatalogItem(Base):
        __tablename__ = 'catalog_item'

        name = Column(String(80), nullable=False)
        id = Column(Integer, primary_key=True)
        description = Column(String(250))
        price = Column(String(8))
        image_name = Column(String(250))
        catalog_id = Column(Integer, ForeignKey('catalog.id'))
        catalog = relationship(Catalog)
        user_id = Column(Integer, ForeignKey('useinfo.id'))
        user = relationship(User)

        @property
        def serialize(self):
            """Return object data in easily serializeable format"""
            return {
                'name': self.name,
                'description': self.description,
                'id': self.id,
                'price': self.price,
                'course': self.course,
            }


engine = create_engine('postgresql://vagrant:Nov-2018@localhost:5432/catalog')

Base.metadata.create_all(engine)

