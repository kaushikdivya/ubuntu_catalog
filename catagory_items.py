

def create_category_items(base_cls):

    class Category_items(base_cls):
        
        __tablename__ = 'catagory_items'
        __table_args__ = {'autoload': True}
    
    return Category_items