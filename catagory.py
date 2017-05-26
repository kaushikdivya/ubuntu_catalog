

def create_category(base_cls):

    class Category(base_cls):
        
        __tablename__ = 'catagory'
        __table_args__ = {'autoload': True}
    
    return Category