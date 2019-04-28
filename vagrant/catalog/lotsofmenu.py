# -*- coding: utf-8 -*-

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from catalogModel import Catalog, Base, CatalogItem

engine = create_engine('postgresql://vagrant:Nov-2018@localhost:5432/catalog')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

catalog1 = Catalog(name="SCRUBS")

session.add(catalog1)
session.commit()

catalogItem1 = CatalogItem(name="Dickies", description="Antimicrobial Mid Rise Flare Leg Pants", price="$12.80", image_name="Sdickies.png", catalog=catalog1)

session.add(catalogItem1)
session.commit()

catalogItem2 = CatalogItem(name="Cherokee",description="Antimicrobial Unisex Snap Front Warm-Up Jacket",price="$18.20", image_name="cherokee.png", catalog=catalog1)

session.add(catalogItem2)
session.commit()

print ("added menu items!")