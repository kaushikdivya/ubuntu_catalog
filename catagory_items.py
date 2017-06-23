

def create_category_items(base_cls):

    class Category_items(base_cls):
        
        __tablename__ = 'catagory_items'
        __table_args__ = {'autoload': True}
    
        @property
        def serialize(self):
            """Return object data in easily serializeable format"""
            return {
                'Category_items_name': self.name,
                'Category_items_id': self.id,
                'Category_items_description': self.description
                }

    return Category_items