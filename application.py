from flask import Flask, render_template, url_for, redirect
import psycopg2
from sqlalchemy.orm import sessionmaker
# from sqlalchemy.ext.declarative import declarative_base
from database import db_connect, create_base
from category import create_category
from category_items import create_category_items
import settings
import sys

app = Flask(__name__)

engine = db_connect()
Base = create_base(engine)
Category = create_category(Base)
Category_items = create_category_items(Base)

Session = sessionmaker(bind = engine)
session = Session()

@app.route('/')
def catelog_home():
    
    all_categories = session.query(Category).all()
    latest_subcatagories = session.query(Category, Category_items
        ).filter(Category.id==Category_items.category_id).order_by(
        Category_items.created_time)
    return render_template('home.html', all_categories=all_categories,
                    latest_subcatagories=latest_subcatagories)

@app.route('/catalog/<category>/<int:category_id>/items/')
def category_list(category, category_id):
    all_categories = session.query(Category).all()
    category_items = session.query(Category_items, Category).filter(
        Category.id==Category_items.category_id).filter(Category.id==category_id)
    state = True
    for category_item in category_items:
        if category_item.Category.name != category:
            print category
            state = False
            sys.exit()
    if state == True:
        return render_template('category_items.html', category=category,
        all_categories=all_categories, category_items=category_items)
    else:
         return redirect(url_for('catelog_home'))
    
@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/catalog/<category>/<int:category_id>/<sub_category>/<int:sub_category_id>/')
def sub_category(category, category_id, sub_category, sub_category_id):
    category_item = session.query(Category, Category_items).filter(Category.id==Category_items.category_id).filter(
        Category_items.id==sub_category_id).one()
    if category == category_item.Category.name and sub_category == category_item.Category_items.name:
        return render_template('item_description.html', category_item=category_item)
    return redirect(url_for('catelog_home'))
    
@app.route('/catalog/add_item')
def add_item():
    return "Add_item"

@app.route('/catalog/<sub_category>/<int:sub_category_id>/edit')
def edit_item(sub_category, sub_category_id):
    return "Edit item"
if __name__ == "__main__":
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)
