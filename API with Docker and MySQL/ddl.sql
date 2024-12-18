-- DDL file
-- baars
-- CS493 - assignment 3 - W24
-- 11/04/2024



-- CREATE TABLES -------------------------------------------
-- Create businesses table
CREATE TABLE IF NOT EXISTS businesses (
    business_id SERIAL NOT NULL, 
    owner_id int NOT NULL, 
    name VARCHAR(50) NOT NULL, 
    street_address VARCHAR(100) NOT NULL, 
    city VARCHAR(50) NOT NULL, 
    state CHAR(2) NOT NULL, 
    zip_code CHAR(5) NOT NULL, 
    PRIMARY KEY (business_id)
    );

-- Create reviews table
CREATE TABLE IF NOT EXISTS reviews (
    review_id SERIAL NOT NULL, 
    user_id int NOT NULL, 
    business_id int NOT NULL, 
    stars int NOT NULL CHECK (stars BETWEEN 0 AND 5),
    review_text VARCHAR(1000), 
    PRIMARY KEY (review_id)
    );



-- DATA REQUESTS - Businesses -------------------------------------------

-- create business
INSERT INTO businesses(owner_id, name, street_address, city, state, zip_code) 
 VALUES (:owner_id, :name, :street_address, :city, :state, :zip_code)

-- update business part 1
SELECT business_id, owner_id, name, street_address, city, state, zip_code FROM businesses WHERE business_id=:business_id
-- update business part 2
UPDATE businesses 
SET owner_id = :owner_id, name = :name, street_address = :street_address, city = :city, state = :state, zip_code = :zip_code 
WHERE business_id = :business_id

-- get business
SELECT business_id, owner_id, name, street_address, city, state, zip_code FROM businesses WHERE business_id=:business_id

-- get businesses
SELECT business_id, owner_id, name, street_address, city, state, zip_code FROM businesses ORDER BY business_id LIMIT :page_limit OFFSET :page_offset

-- delete business
DELETE FROM businesses WHERE business_id=:business_id

-- List all businesses filtered by Owner
SELECT business_id, owner_id, name, street_address, city, state, zip_code FROM businesses WHERE owner_id=:owner_id



-- DATA REQUESTS - Reviews -------------------------------------------

-- create review
INSERT INTO reviews(user_id, business_id, stars, review_text) 
 VALUES (:user_id, :business_id, :stars, :review_text)

-- update review - part 1
SELECT review_id, user_id, business_id, stars, review_text FROM reviews WHERE review_id=:review_id
-- update review - part 2
UPDATE reviews 
SET user_id = :user_id, business_id = :business_id, stars = :stars, review_text = :review_text 
WHERE review_id = :review_id

-- get review
SELECT review_id, user_id, business_id, stars, review_text FROM reviews WHERE review_id=:review_id

-- get reviews filtered by user
SELECT review_id, user_id, business_id, stars, review_text FROM reviews WHERE user_id=:user_id

-- delete business
DELETE FROM reviews WHERE review_id=:review_id




