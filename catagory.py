

def create_category(base_cls):

    class Category(base_cls):
        
        __tablename__ = 'catagory'
        __table_args__ = {'autoload': True}

        @property
        def serialize(self):
            """Return object data in easily serializeable format"""
            return {
                'Category_name': self.name,
                'Category_id': self.id
            }
    
    return Category