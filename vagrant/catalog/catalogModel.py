from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)


Base = declarative_base()

Base = declarative_base()
key = 'super_key'


class User(Base):
    __tablename__ = 'useinfo'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(key, expires_in = expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        user_id = data['id']
        return user_id

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
            }


engine = create_engine('postgresql://vagrant:Nov-2018@localhost:5432/catalog')

Base.metadata.create_all(engine)

