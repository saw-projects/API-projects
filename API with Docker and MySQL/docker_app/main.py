# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import logging
import os

from flask import Flask, request

import sqlalchemy

from connect_connector import connect_with_connector

# LODGINGS = 'businesses'
# ERROR_NOT_FOUND = {'Error' : 'No business with this id exists'}

#ENTITIES
BUSINESSES = 'businesses'
REVIEWS = 'reviews'
#400 ERROR
ERROR_BAD_REQUEST = {"Error": "The request body is missing at least one of the required attributes"} #400
#404 ERROR
ERROR_NOT_FOUND_BUSINESS = {"Error": "No business with this business_id exists"} 
ERROR_NOT_FOUND_REVIEW = {"Error" : "No review with this review_id exists"}
#409 ERROR
ERROR_CONFLICT = {"Error": "You have already submitted a review for this business. You can update your previous review, or delete it and submit a new review"}
#PROPERTIES
BUSINESS_PROPERTIES = ['owner_id', 'name', 'street_address', 'city', 'state', 'zip_code']
REVIEW_PROPERTIES = ['user_id', 'business_id', 'stars', 'review_text']

app = Flask(__name__)

logger = logging.getLogger()

# Sets up connection pool for the app
def init_connection_pool() -> sqlalchemy.engine.base.Engine:
    if os.environ.get('INSTANCE_CONNECTION_NAME'):
        return connect_with_connector()
        
    raise ValueError(
        'Missing database connection type. Please define INSTANCE_CONNECTION_NAME'
    )

# This global variable is declared with a value of `None`
db = None

# Initiates connection to database
def init_db():
    global db
    db = init_connection_pool()

# create 'businesses' and 'reviews' table in database if it does not already exist
def create_table(db: sqlalchemy.engine.base.Engine) -> None:
    with db.connect() as conn:
        conn.execute(
            sqlalchemy.text(
                'SET default_storage_engine=INNODB;'
            )
        )
        conn.commit()
        conn.execute(
            sqlalchemy.text(
                'CREATE TABLE IF NOT EXISTS businesses'
                '(business_id SERIAL NOT NULL, '
                'owner_id int NOT NULL, '
                'name VARCHAR(50) NOT NULL, '
                'street_address VARCHAR(100) NOT NULL, '
                'city VARCHAR(50) NOT NULL, '
                'state CHAR(2) NOT NULL, '
                'zip_code CHAR(5) NOT NULL, '
                'PRIMARY KEY (business_id));'
            )
        )
        conn.commit()
        # the businesses table must be created before the reviews table can be created.
        conn.execute(
            sqlalchemy.text(
                'CREATE TABLE IF NOT EXISTS reviews ('
                'review_id SERIAL NOT NULL, '
                'user_id int NOT NULL, '
                'business_id bigint NOT NULL, '
                'stars int NOT NULL CHECK (stars BETWEEN 0 AND 5), '
                'review_text VARCHAR(1000), '
                'PRIMARY KEY (review_id));'
            )
        )
        conn.commit()
        # Use foreign key constrain to delete on CASCADE
        # conn.execute(
        #     sqlalchemy.text(
        #         'ALTER TABLE reviews '
        #         'ADD FOREIGN KEY (business_id) REFERENCES businesses(business_id) ON DELETE CASCADE;'
        #     )
        # )
        # conn.commit()


#---FUNCTIONS------------------------------------------------------------------------------------#
def invalid_content(input, properties):
    input_properties =[]
    for i in input:
        input_properties.append(i)
    for property in properties:
        if property not in input_properties:
            if property != "review_text":
                return True
    return False

def review_exists(review_content):
    review_user_id = review_content['user_id']
    review_business_id = review_content['business_id']
    #get all reviews
    #TODO
    with db.connect() as conn:
        stmt = sqlalchemy.text(
                'SELECT review_id, user_id, business_id, stars, review_text FROM reviews WHERE user_id=:user_id AND business_id=:business_id'
            )
        row = conn.execute(stmt, parameters={'user_id': review_user_id, 'business_id': review_business_id}).one_or_none()
    #check if there is an existing review for the given user and business
    if row is None:
        return False
    else:
        return True

def business_doesnt_exist(business_content):
    business_id = business_content['business_id']
    business = get_business(business_id) # returns business dict or error
    if business == (ERROR_NOT_FOUND_BUSINESS, 404):
        return True
    else:
        return False
    
def delete_business_reviews(business_id):
    """Helper function to delete all reviews associated with a deleted business."""
    reviews = get_reviews_by_business(business_id)
    # find all reviews for the business_id
    for review in reviews:
        review_id = review['review_id']
        delete_review(review_id)
    return True

def get_reviews_by_business(business_id):
    """Helper for delete_business_reviews function."""
    with db.connect() as conn:
        stmt = sqlalchemy.text(
                'SELECT review_id, business_id FROM reviews WHERE business_id=:business_id'
            )
        
        stmt = stmt.bindparams(business_id=business_id)

        reviews = []
        rows = conn.execute(stmt)
        # Iterate through the result
        for row in rows:
            review = row._asdict()
            reviews.append(review)
        return reviews

def generate_self_url(request_url, url_extension):
    """Concatenates a URL to return in the response."""
    return request_url + "/" + str(url_extension)


#---ROUTING------------------------------------------------------------------------------------#
@app.route('/')
def index():
    return 'Please navigate to /businesses or /reviews to use this API'

#---BUSINESSES------------------------------------------------------------------------------------#
# CREATE A BUSINESS (1)
@app.route('/' + BUSINESSES, methods=['POST'])
def post_businesses():
    content = request.get_json()
    if invalid_content(content, BUSINESS_PROPERTIES):
        return (ERROR_BAD_REQUEST, 400)
    else:
        # Starter code provided starts here. All "lodging" references changed to "business"
        try:
            # Using a with statement ensures that the connection is always released
            # back into the pool at the end of statement (even if an error occurs)
            with db.connect() as conn:
                # Preparing a statement before hand can help protect against injections.
                stmt = sqlalchemy.text(
                    'INSERT INTO businesses(owner_id, name, street_address, city, state, zip_code) '
                    ' VALUES (:owner_id, :name, :street_address, :city, :state, :zip_code)'
                )
                # connection.execute() automatically starts a transaction
                conn.execute(stmt, parameters={
                                            'owner_id': content['owner_id'],
                                            'name': content['name'],
                                            'street_address': content['street_address'],
                                            'city': content['city'],
                                            'state': content['state'],
                                            'zip_code': content['zip_code']
                                            })
                # The function last_insert_id() returns the most recent value
                # generated for an `AUTO_INCREMENT` column when the INSERT 
                # statement is executed
                stmt2 = sqlalchemy.text('SELECT last_insert_id()')
                # scalar() returns the first column of the first row or None if there are no rows
                business_id = conn.execute(stmt2).scalar()
                # Remember to commit the transaction
                conn.commit()

                # concatenate full URL 
                request_url = request.url
                url_extension = business_id
                self_url = generate_self_url(request_url, url_extension)
                # new_item_url = request_url + "/" + str(content['owner_id'])

        except Exception as e:
            logger.exception(e)
            return ({'Error': 'Unable to create business'}, 500)

        return ({'id': business_id,
                'owner_id': content['owner_id'],
                'name': content['name'],
                'street_address': content['street_address'],
                'city': content['city'],
                'state': content['state'],
                'zip_code': content['zip_code'],
                'self': self_url
    }, 201)

# Get all businesses
@app.route('/' + BUSINESSES, methods=['GET'])
def get_businesses():
    with db.connect() as conn:
        page_limit = request.args.get('limit', default=3, type=int)
        page_offset = request.args.get('offset', default=0, type=int)
        stmt = sqlalchemy.text(
                'SELECT business_id, owner_id, name, street_address, city, state, zip_code FROM businesses ORDER BY business_id LIMIT :page_limit OFFSET :page_offset'
            )
        stmt = stmt.bindparams(page_limit=page_limit, page_offset=page_offset)

        # add return url
        request_url = request.url

        businesses = []
        rows = conn.execute(stmt)
        # Iterate through the result
        for row in rows:
            # Turn row into a dictionary
            business = row._asdict()
            # add self_url to each business
            base_url = request_url.split('?')[0] #remove previous limit and offset from url if necessary
            self_url = base_url + '/' + str(business['business_id'])
            business["self"] = self_url
            
            business['id'] = business['business_id']
            business.pop('business_id')
            # business['zip_code'] = int(business['zip_code'])
            businesses.append(business)

        #build return response
        page_offset += page_limit
        return_response = {}
        return_response["entries"] = businesses
        # base_url = request_url.split('?')[0] 
        return_response["next"] = base_url + '?offset=' + str(page_offset) + '&limit=' + str(page_limit)
        return return_response

# Get a business
@app.route('/' + BUSINESSES + '/<int:id>', methods=['GET'])
def get_business(id):
    with db.connect() as conn:
        stmt = sqlalchemy.text(
                'SELECT business_id, owner_id, name, street_address, city, state, zip_code FROM businesses WHERE business_id=:business_id'
            )
        # one_or_none returns at most one result or raise an exception.
        # returns None if the result has no rows.
        row = conn.execute(stmt, parameters={'business_id': id}).one_or_none()
        if row is None:
            return ERROR_NOT_FOUND_BUSINESS, 404
        else:
            business = row._asdict()
            # add return url
            request_url = request.url
            # url_extension = business['business_id']
            # self_url = generate_self_url(request_url, url_extension)
            self_url = request_url
            business["self"] = self_url

            business['id'] = business['business_id']
            business.pop('business_id')
            # business['zip_code'] = int(business['zip_code'])
            return business

# Update a business
@app.route('/' + BUSINESSES + '/<int:id>', methods=['PUT'])
def put_business(id):
    content = request.get_json()
    if invalid_content(content, BUSINESS_PROPERTIES):
        return (ERROR_BAD_REQUEST, 400)
    else:
        with db.connect() as conn:
            stmt = sqlalchemy.text(
                    'SELECT business_id, owner_id, name, street_address, city, state, zip_code FROM businesses WHERE business_id=:business_id'
                )
            row = conn.execute(stmt, parameters={'business_id': id}).one_or_none()
            if row is None:
                return ERROR_NOT_FOUND_BUSINESS, 404
            else:
                content = request.get_json()
                # build self_url to return in response
                # concatenate full URL 
                request_url = request.url
                self_url = request_url
                # continute with text sql
                stmt = sqlalchemy.text(
                    'UPDATE businesses '
                    'SET owner_id = :owner_id, name = :name, street_address = :street_address, city = :city, state = :state, zip_code = :zip_code '
                    'WHERE business_id = :business_id'
                )
                conn.execute(stmt, parameters={
                                        'owner_id': content['owner_id'],
                                        'name': content['name'],
                                        'street_address': content['street_address'],
                                        'city': content['city'],
                                        'state': content['state'],
                                        'zip_code': content['zip_code'],
                                        'business_id': id})
                conn.commit()
                return {'id': id, 
                        'owner_id': content['owner_id'],
                        'name': content['name'],
                        'street_address': content['street_address'],
                        'city': content['city'],
                        'state': content['state'],
                        'zip_code': content['zip_code'],
                        'self': self_url}

# Delete a business
@app.route('/' + BUSINESSES + '/<int:id>', methods=['DELETE'])
def delete_business(id):
     with db.connect() as conn:
        # delete business
        stmt = sqlalchemy.text(
                'DELETE FROM businesses WHERE business_id=:business_id'
            )
        
        result = conn.execute(stmt, parameters={'business_id': id})
        conn.commit()
        # delete all reviews associated with this business
        # result.rowcount value will be the number of rows deleted.
        # For our statement, the value be 0 or 1 because business_id is
        # the PRIMARY KEY
        if result.rowcount == 1:
            # delete all reviews associated with deleted business
            try:
                delete_business_reviews(business_id=id)
            except:
                nothing = 0
            return ('', 204)
        else:
            return ERROR_NOT_FOUND_BUSINESS, 404      

# LIST ALL BUSINESSES FILTERED BY OWNER (6)
@app.route('/owners/' + '<int:owner_id>/' + BUSINESSES, methods=['GET'])
def get_businesses_by_owner(owner_id):
    with db.connect() as conn:
        stmt = sqlalchemy.text(
                'SELECT business_id, owner_id, name, street_address, city, state, zip_code FROM businesses WHERE owner_id=:owner_id'
            )
        
        stmt = stmt.bindparams(owner_id=owner_id)

        
        # add return url
        request_url = request.url
        base_url = request_url.split('owners/')[0]

        businesses = []
        rows = conn.execute(stmt)
        # Iterate through the result
        for row in rows:
            # Turn row into a dictionary
            business = row._asdict()
            # add self_url to each business
            self_url = base_url + BUSINESSES + '/' + str(business['business_id'])
            business["self"] = self_url
            businesses.append(business)

            business['id'] = business['business_id']
            business.pop('business_id')

        return businesses

#---REVIEWS------------------------------------------------------------------------------------#
# CREATE A REVIEW (7)
@app.route('/' + REVIEWS, methods=['POST'])
def post_reviews():
    content = request.get_json()
    if invalid_content(content, REVIEW_PROPERTIES):
        return (ERROR_BAD_REQUEST, 400)
    elif business_doesnt_exist(content):
        return (ERROR_NOT_FOUND_BUSINESS, 404)
    elif review_exists(content):
        return (ERROR_CONFLICT, 409)
    else:
        # Starter code provided starts here. All "lodging" references changed to "business"
        try:
            # Using a with statement ensures that the connection is always released
            # back into the pool at the end of statement (even if an error occurs)
            try:
                exist_check = content['review_text']
            except:
                content['review_text'] = ''
            with db.connect() as conn:
                # Preparing a statement before hand can help protect against injections.
                stmt = sqlalchemy.text(
                    'INSERT INTO reviews(user_id, business_id, stars, review_text) '
                    ' VALUES (:user_id, :business_id, :stars, :review_text)'
                )
                # connection.execute() automatically starts a transaction
                conn.execute(stmt, parameters={
                                            'user_id': content['user_id'],
                                            'business_id': content['business_id'],
                                            'stars': content['stars'],
                                            'review_text': content['review_text']
                                            })
                # The function last_insert_id() returns the most recent value
                # generated for an `AUTO_INCREMENT` column when the INSERT 
                # statement is executed
                stmt2 = sqlalchemy.text('SELECT last_insert_id()')
                # scalar() returns the first column of the first row or None if there are no rows
                review_id = conn.execute(stmt2).scalar()
                # Remember to commit the transaction
                conn.commit()

                # concatenate full URL for self and for business
                request_url = request.url
                self_url = generate_self_url(request_url, review_id)
                request_url = request_url.split('reviews')[0]
                business_url = request_url + 'businesses/' + str(content['business_id'])

        except Exception as e:
            logger.exception(e)
            return ({'Error': 'Unable to create review'}, 500)

        return ({'id': review_id,
                'user_id': content['user_id'],
                'business': business_url,
                'stars': content['stars'],
                'review_text': content['review_text'],
                'self': self_url
    }, 201)            

# GET A REVIEW
@app.route('/' + REVIEWS + '/<int:id>', methods=['GET'])
def get_review(id):
    with db.connect() as conn:
        stmt = sqlalchemy.text(
                'SELECT review_id, user_id, business_id, stars, review_text FROM reviews WHERE review_id=:review_id'
            )
        # one_or_none returns at most one result or raise an exception.
        # returns None if the result has no rows.
        row = conn.execute(stmt, parameters={'review_id': id}).one_or_none()
        if row is None:
            return ERROR_NOT_FOUND_REVIEW, 404
        else:
            review = row._asdict()
            # add return url
            request_url = request.url
            # url_extension = business['business_id']
            # self_url = generate_self_url(request_url, url_extension)
            self_url = request_url
            review["self"] = self_url
            request_url = request_url.split('reviews')[0]
            business_url = request_url + 'businesses/' + str(review['business_id'])
            # business['zip_code'] = int(business['zip_code'])
            return ({'id': review['review_id'],
                'user_id': review['user_id'],
                'business': business_url,
                'stars': review['stars'],
                'review_text': review['review_text'],
                'self': self_url
    }, 200)  

# Update a review
@app.route('/' + REVIEWS + '/<int:id>', methods=['PUT'])
def put_review(id):
    content = request.get_json()
    try:
        review_valid = content['stars']
    except:
        review_valid = False
    if review_valid == False:
        return (ERROR_BAD_REQUEST, 400)
    # elif review_exists(content) is False:
    #     return (ERROR_NOT_FOUND_REVIEW, 404)
    else:
        with db.connect() as conn:
            stmt = sqlalchemy.text(
                    'SELECT review_id, user_id, business_id, stars, review_text FROM reviews WHERE review_id=:review_id'
                )
            # one_or_none returns at most one result or raise an exception.
            # returns None if the result has no rows.
            row = conn.execute(stmt, parameters={'review_id': id}).one_or_none()
            if row is None:
                return ERROR_NOT_FOUND_REVIEW, 404
            else:
                content = request.get_json()
                # build self_url to return in response
                # concatenate full URL 
                row = row._asdict()
                request_url = request.url
                url_extension = id # id = business_id
                self_url = request_url
                request_url = request_url.split('reviews')[0]
                business_url = request_url + 'businesses/' + str(row['business_id'])
                # continute with text sql
                stmt = sqlalchemy.text(
                    'UPDATE reviews '
                    'SET user_id = :user_id, business_id = :business_id, stars = :stars, review_text = :review_text '
                    'WHERE review_id = :review_id'
                )
                # create complete dictionary to send in update request
                for key, value in row.items():
                        if key not in content:
                            content[key] = value

                conn.execute(stmt, parameters={
                                        'user_id': content['user_id'],
                                        'business_id': content['business_id'],
                                        'stars': content['stars'],
                                        'review_text': content['review_text'],
                                        'review_id': id})
                conn.commit()
                return {'id': content['review_id'],
                        'user_id': content['user_id'],
                        'business': business_url,
                        'stars': content['stars'],
                        'review_text': content['review_text'],
                        'self': self_url}

# Delete a review
@app.route('/' + REVIEWS + '/<int:id>', methods=['DELETE'])
def delete_review(id):
     with db.connect() as conn:
        stmt = sqlalchemy.text(
                'DELETE FROM reviews WHERE review_id=:review_id'
            )
        
        result = conn.execute(stmt, parameters={'review_id': id})
        conn.commit()
        # result.rowcount value will be the number of rows deleted.
        # For our statement, the value be 0 or 1 because business_id is
        # the PRIMARY KEY
        if result.rowcount == 1:
            return ('', 204)
        else:
            return ERROR_NOT_FOUND_REVIEW, 404  

# LIST ALL REVIEWS FILTERED BY USER (6)
@app.route('/users/' + '<int:user_id>/' + REVIEWS, methods=['GET'])
def get_reviews_by_user(user_id):
    with db.connect() as conn:
        stmt = sqlalchemy.text(
                'SELECT review_id, user_id, business_id, stars, review_text FROM reviews WHERE user_id=:user_id'
            )
        stmt = stmt.bindparams(user_id=user_id)

        # add return url
        request_url = request.url
        base_url = request_url.split('users')[0]

        reviews = []
        rows = conn.execute(stmt)
        # Iterate through the result
        for row in rows:
            # Turn row into a dictionary
            review = row._asdict()
            # add self_url to each business
            business_url = base_url + BUSINESSES + '/' + str(review['business_id'])
            self_url = base_url + REVIEWS + '/' + str(review['review_id'])
            review["self"] = self_url
            review['business'] = business_url
            review['id'] = review['review_id']

            review.pop('business_id')
            review.pop('review_id')

            # add dict to list of businesses
            reviews.append(review)

        return reviews 

if __name__ == '__main__':
    init_db()
    create_table(db)
    app.run(host='0.0.0.0', port=8000, debug=True)
