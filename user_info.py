def create_user(base_cls):

    class User_info(base_cls):
        
        __tablename__ = 'user_info'
        __table_args__ = {'autoload': True}
    
    return User_info