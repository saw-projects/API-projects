from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
import io

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
client = datastore.Client()

PHOTO_BUCKET='hw6_photos_baars'

# ENTITIES
USERS = "users"
COURSE = "course"
COURSES = "courses"
ENROLLMENTS = 'enrollments'
ADMIN = "admin"
INSTRUCTOR = "instructor"
STUDENT = "student"
# ERROR MESSAGES
#400 ERROR
ERROR_BAD_REQUEST = {"Error": "The request body is invalid"} #400
#401 ERROR
ERROR_UNAUTHORIZED = {"Error": "Unauthorized"} #401
#403 ERROR
ERROR_NO_PERMISSION = {"Error": "You don't have permission on this resource"} #403
#404 ERROR
ERROR_NOT_FOUND = {"Error": "Not found"} #404
# #409 ERROR
ERROR_409 = {"Error": "Enrollment data is invalid"}
# ERROR_CONFLICT = {"Error": "You have already submitted a review for this business. You can update your previous review, or delete it and submit a new review"}
#PROPERTIES
LOGIN_PROPERTIES = ['username', 'password']
COURSE_PROPERTIES = ['subject', 'number', 'title', 'term', 'instructor_id']

# Response Status Code JSON Error Message
# 400 {"Error": "The request body is invalid"}
# 401 {"Error": "Unauthorized"}
# 403 {"Error": "You don't have permission on this resource"}
# 404 {"Error": "Not found"}

# Update the values of the following 3 variables
CLIENT_ID = '5Tw5OxWooUF2syW3et94M8LnTrHDurpd'
CLIENT_SECRET = 'SSfnoyjyEYy2bl-kakaIr2R7-L7v4hmXo_wgxcXZMk0lJWJYXchuiNfwd_rmU3W0'
DOMAIN = 'dev-7pnnh4jfs3fr0nbi.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

@app.route('/')
def index():
    return "Please navigate to /users, /course, or /courses to use this API."

#---USERS: Endpoints 1 to 6 ------------------------------------------------------------------------------------#

# 1 - USER LOGIN
@app.route('/users/login', methods=['POST'])
def user_login():
    """
    Protection: Pre-created Auth0 users with username and password
    Description: Use Auth0 to issue JWTs.
    """
    if request.method == 'POST':
        content = request.get_json()
        #return 400 if invalid request body
        if invalid_content(content, LOGIN_PROPERTIES):
            return ERROR_BAD_REQUEST, 400
        else:
            content = request.get_json()
            username = content["username"]
            password = content["password"]
            body = {'grant_type':'password','username':username,
                    'password':password,
                    'client_id':CLIENT_ID,
                    'client_secret':CLIENT_SECRET
                }
            headers = { 'content-type': 'application/json' }
            url = 'https://' + DOMAIN + '/oauth/token'
            r = requests.post(url, json=body, headers=headers)
            # payload = jsonify(r.text)
            payload = json.loads(r.text)
            try:
                id_token = {"token": payload['id_token']} # the JWT
            except:
                return ERROR_UNAUTHORIZED, 401
            return id_token, 200
    else:
        return jsonify(error='Method not recogonized')

# 2 - GET ALL USERS
@app.route('/' + USERS, methods=['GET'])
def get_users():
    """
    Protection: Admin Only
    Description: Summary information of all 9 users. No info about avatar or courses.
    """
    if request.method == 'GET':
        # verify JWT and return 401 if invalid
        try:
            payload = verify_jwt(request)
        except:
            return ERROR_UNAUTHORIZED, 401
        # sub of requester
        request_sub = payload['sub']
        # sub of admin acct
        query = client.query(kind=USERS)
        query.add_filter('role', '=', ADMIN)
        results = list(query.fetch())
        admin_sub = results[0]['sub']
        if request_sub!=admin_sub: # if requested by admin
            return ERROR_NO_PERMISSION, 403
        else:
            # get all users 
            query = client.query(kind=USERS)
            results = list(query.fetch())
            # return array of objects
            return_array = []
            for r in results:
            # only return id, role, sub. Allows more data to be stored if needed.
                r['id'] = r.key.id
                return_array.append(
                    {
                    'id': r['id'],
                    'role': r['role'],
                    'sub': r['sub']  
                    }
                )
            return return_array
    else: 
        return jsonify(error='Method not recogonized')

# 3 - GET A USER
@app.route('/' + USERS + '/<int:id>', methods=['GET'])
def get_user(id):
    """
    Protection: Admin. Or user with JWT matching ID
    Description: Detailed info about the user, including avatar (if any) and courses (for instructors and students)
    """
    if request.method == 'GET':
        # 1.) verify if JWT valid - RETURN 401 if not
        try:
            payload = verify_jwt(request)
        except:
            return ERROR_UNAUTHORIZED, 401
        # 2.) get data
         # sub of requester
        request_sub = payload['sub']
        # get user from datastore
        user_key = client.key(USERS, id)
        user = client.get(key=user_key)
        user_sub = user['sub']
        user_role = user['role']
        # 2.a.) JWT Valid  - RETURN 403 if user doens't match or is not admin
        if request_sub==user_sub or user_role==ADMIN:
            # get base URL for links to avatar and courses if needed
            request_url = request.url
            # get user info and build return dict
            user['id'] = user.key.id
            return_dict = {
                'id': user['id'],
                'role': user['role'],
                'sub': user['sub']  
                }
            # students and instructors return list of courses. Admin doesn't
            if user_role == STUDENT or user_role == INSTRUCTOR:
                return_dict['courses'] = []
                base_url = request.url.split('/')[0]
                if user_role == STUDENT:
                    print(id)
                    enrollment_query = client.query(kind=ENROLLMENTS)
                    enrollment_query.add_filter('student_id', '=', id)
                    enrollment_for_student = list(enrollment_query.fetch())
                    print(enrollment_for_student)
                    for enrollment in enrollment_for_student:
                        course_url = base_url +'/' + COURSES + '/' + str(enrollment['course_id'])
                        return_dict['courses'].append(course_url)
                elif user_role == INSTRUCTOR:
                    course_query = client.query(kind=COURSES)
                    course_query.add_filter('instructor_id', '=', id)
                    courses_for_instructor = list(course_query.fetch())
                    for course in courses_for_instructor:
                        course_url = base_url +'/' + COURSES + '/' + str(course.key.id)
                        return_dict['courses'].append(course_url)
            try:
                if user['has_avatar'] == "True":
                    avatar_url = request_url + '/avatar'
                    return_dict['avatar_url'] = avatar_url
            except:
                pass
            return return_dict, 200
        else:
            return ERROR_NO_PERMISSION, 403
    else: 
        return jsonify(error='Method not recogonized')

# 4 - Create/Update a user's avatar
@app.route('/' + USERS + '/<int:id>'  + '/avatar', methods=['POST'])
def put_user_avatar(id):
    """
    Protection: User with JWT matching ID
    Description: Upload file to Google Cloud Storage
    """
    if request.method == 'POST':
        # return 400 on failure
        if 'file' not in request.files:
            return (ERROR_BAD_REQUEST, 400)
        # test if jwt valid - or return 401
        try:
            payload = verify_jwt(request)
        except:
            return ERROR_UNAUTHORIZED, 401
         # sub of requester
        request_sub = payload['sub']
        # get user from datastore
        user_key = client.key(USERS, id)
        user = client.get(key=user_key)
        user_sub = user['sub']
        # user_key = client.key(USERS, id)
        # user = client.get(key=user_key)
        # 403 of no permission
        if request_sub != user_sub:
            return ERROR_NO_PERMISSION, 403
        else:
            # copied from example code in Exploration
            file_obj = request.files['file']
            # If the multipart form data has a part with name 'tag', set the
            # value of the variable 'tag' to the value of 'tag' in the request.
            # Note we are not doing anything with the variable 'tag' in this
            # example, however this illustrates how we can extract data from the
            # multipart form data in addition to the files.
            if 'tag' in request.form:
                tag = request.form['tag']
            # Create a storage client
            storage_client = storage.Client()
            # Get a handle on the bucket
            bucket = storage_client.get_bucket(PHOTO_BUCKET)
            # Check if an avatar exists, and update if it already exists
            try:
                if user['has_avatar'] == "True":
                    delete_image('avatar_' + str(id))
            finally:
                # Create a blob object for the bucket with the name of the file
                file_obj.filename = 'avatar_' + str(id)
                blob = bucket.blob(file_obj.filename)
                # Position the file_obj to its beginning
                file_obj.seek(0)
                # Upload the file into Cloud Storage
                blob.upload_from_file(file_obj)
                # store to datacloud
                user.update({
                        'sub': user['sub'],
                        'role': user['role'],
                        'has_avatar': "True",
                        'file_name': file_obj.filename
                    })
                client.put(user)
                # return URL of avatar
                base_url = request.url
                response_url = {"avatar_url": base_url}
                return response_url, 200
    else: 
        return jsonify(error='Method not recogonized')

# 5 - Get a user's avatar
@app.route('/' + USERS + '/<int:id>'  + '/avatar', methods=['GET'])
def get_user_avatar(id):
    """
    Protection: User with JWT matching ID
    Description: Read and return file from Google Cloud Storage
    """
    if request.method == 'GET':
        # test if jwt valid - or return 401
        try:
            payload = verify_jwt(request)
        except:
            return ERROR_UNAUTHORIZED, 401
         # sub of requester
        request_sub = payload['sub']
        # get user from datastore
        user_key = client.key(USERS, id)
        user = client.get(key=user_key)
        user_sub = user['sub']
        user_key = client.key(USERS, id)
        user = client.get(key=user_key)
        # 403 of no permission
        if request_sub != user_sub:
            return ERROR_NO_PERMISSION, 403
        else:
            try:
                if user['has_avatar'] == "True":
                    # 2.b.) JWT Valid  - RETURN 403 if business ID exist but Owner's don't match
                    file_name = 'avatar_' + str(id)
                    storage_client = storage.Client()
                    bucket = storage_client.get_bucket(PHOTO_BUCKET)
                    # Create a blob with the given file name
                    blob = bucket.blob(file_name)
                    # Create a file object in memory using Python io package
                    file_obj = io.BytesIO()
                    # Download the file from Cloud Storage to the file_obj variable
                    blob.download_to_file(file_obj)
                    # Position the file_obj to its beginning
                    file_obj.seek(0)
                    # Send the object as a file in the response with the correct MIME type and file name
                    return send_file(file_obj, mimetype='image/x-png', download_name=file_name), 200
                else:
                    return ERROR_NOT_FOUND, 404
            except:
                return ERROR_NOT_FOUND, 404
    else: 
        return jsonify(error='Method not recogonized')

# 6 - Delete a User's avatar
@app.route('/' + USERS + '/<int:id>' + '/avatar', methods=['DELETE'])
def delete_user_avatar(id):
    """
    Protection: User with JWT matching id
    Description: Delete file from Google Cloud Storage.
    """
    if request.method == 'DELETE':
        # 1.) verify if JWT valid - RETURN 401 if not
        # test if jwt valid - or return 401
        try:
            payload = verify_jwt(request)
        except:
            return ERROR_UNAUTHORIZED, 401
         # sub of requester
        request_sub = payload['sub']
        # get user from datastore
        user_key = client.key(USERS, id)
        user = client.get(key=user_key)
        user_sub = user['sub']
        user_key = client.key(USERS, id)
        user = client.get(key=user_key)
        # 403 of no permission
        if request_sub != user_sub:
            return ERROR_NO_PERMISSION, 403
        else:
            try:
                if user['has_avatar'] == "True":
                    file_name = 'avatar_' + str(id)
                    delete_image(file_name)
                    user.update({
                        'sub': user['sub'],
                        'role': user['role'],
                        'has_avatar': "False",
                        'file_name': 'None'
                    })
                    client.put(user)
                    return '', 204
                else:
                    return ERROR_NOT_FOUND, 404
            except:
                return ERROR_NOT_FOUND, 404
    else: 
        return jsonify(error='Method not recogonized')

#---COURSES: Endpoints 7 to 8 ------------------------------------------------------------------------------------#

# 7 - Create a Course
@app.route('/' + COURSES, methods=['POST'])
def post_course():
    """
    Protection: Admin only
    Description: create a course
    """
    if request.method == 'POST':
        content = request.get_json()
        # Error 400 if JWT missing
        # test if jwt valid - or return 401
        try:
            payload = verify_jwt(request)
        except:
            return ERROR_UNAUTHORIZED, 401
         # sub of requester
        request_sub = payload['sub']
        # get admin from datastore
        query = client.query(kind=USERS)
        query.add_filter('role', '=', ADMIN)
        admin = list(query.fetch())[0]
        
        if request_sub != admin['sub']:
            return ERROR_NO_PERMISSION, 403
        else:
            # get instructor from datastore
            query = client.query(kind=USERS)
            query.add_filter('role', '=', INSTRUCTOR)
            instructors = list(query.fetch())
            course_instructor_exists = False
            for instructor in instructors:
                if instructor.key.id == content['instructor_id']:
                    course_instructor_exists = True
            if invalid_content(content, COURSE_PROPERTIES):
                return (ERROR_BAD_REQUEST, 400)
            elif course_instructor_exists == False:
                return (ERROR_BAD_REQUEST, 400)
            else:
                #finally post new course
                new_course = datastore.Entity(key=client.key(COURSES))
                new_course.update({
                    'subject': content['subject'],
                    'instructor_id': content['instructor_id'],
                    'number': content['number'],
                    'term': content['term'],
                    'title': content['title']
                })
                client.put(new_course)
                new_course['id'] = new_course.key.id
                # develop URL
                base_url = request.url
                self_url = base_url + '/' + str(new_course['id'])
                new_course['self'] = self_url
                return (new_course, 201)
    else:
        return jsonify(error='Method not recogonized')

# 8 - GET ALL COURSES
@app.route('/' + COURSES, methods=['GET'])
def get_courses():
    """
    Protection: unprotected
    Description: Paginated using offset/limit. Page size is 3. Ordered by “subject.” Doesn’t return info on course enrollment.
    """
    if request.method == 'GET':
        page_limit = request.args.get('limit', default=3, type=int)
        page_offset = request.args.get('offset', default=0, type=int)
        # get all businesses and filter by owner
        query = client.query(kind=COURSES)
        query.order = ['subject']
        results = list(query.fetch())
        # concatenate full URL 
        request_url = request.url
        base_url = request_url.split('?')[0] #remove previous limit and offset from url if necessary
        # return array of objects
        sorted_return_array = []
        for r in results:
            # build self_url
            r['id'] = r.key.id
            url_extension = str(r['id'])
            self_url = base_url + '/' + url_extension
            # build return array w/ inspection_score
            sorted_return_array.append(
                {
                'id': r['id'],
                'instructor_id': r['instructor_id'],
                'number': r['number'],
                'subject': r['subject'],
                'term': r['term'],
                'title': r['title'],
                'self': self_url    
                }
            )
        # build return response - sort and then paginate
        # sorted_return_array = sorted(return_array, key=lambda d: d['subject'])
        if page_limit <= len(sorted_return_array):
            paginated_array = sorted_return_array[page_offset:(page_limit + page_offset)]
        else:
            paginated_array = sorted_return_array[page_offset:len(sorted_return_array)]
        page_offset += page_limit
        next_page_url = base_url + '?offset=' + str(page_offset) + '&limit=' + str(page_limit)
        return_dict = {COURSES: paginated_array, 'next': next_page_url}
        return return_dict
    else: 
        return jsonify(error='Method not recogonized')

#---COURSE: Endpoints 9 to 11 ------------------------------------------------------------------------------------#

# 9 - GET A COURSE
@app.route('/' + COURSES + '/<int:course_id>', methods=['GET'])
def get_course(course_id):
    """
    Protection: Unprotected
    Description: Doesnt return info on course enrollment.
    """
    if request.method == 'GET':
        # concatenate full URL 
        request_url = request.url
        # get course
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        # 2.a.) JWT Valid  - RETURN 403 if business ID doesn't exist
        if course is None:
            return ERROR_NOT_FOUND, 404
        else:
            # make return self_url
            request_url = request.url
            self_url = request_url
            # return business
            return ({
            'id': course_id,
            'instructor_id': course['instructor_id'],
            'number': course['number'],
            'subject': course['subject'],
            'term': course['term'],
            'title': course['title'],
            'self': self_url
            }, 200)
    else: 
        return jsonify(error='Method not recogonized')

# 10 - Update a course
@app.route('/' + COURSES + '/<int:course_id>', methods=['PATCH'])
def udpate_course(course_id):
    """
    Protection: Admin only
    Description: Partial Update
    """
    if request.method == 'PATCH':
        content = request.get_json()
        # Error 400 if JWT missing
        # test if jwt valid - or return 401
        try:
            payload = verify_jwt(request)
        except:
            return ERROR_UNAUTHORIZED, 401
         # sub of requester
        request_sub = payload['sub']
        # get admin from datastore
        query = client.query(kind=USERS)
        query.add_filter('role', '=', ADMIN)
        admin = list(query.fetch())[0]
        
        if request_sub != admin['sub']:
            return ERROR_NO_PERMISSION, 403
        else:
            try:
                course_key = client.key(COURSES, course_id)
                course = client.get(key=course_key)
                if course == None:
                    return ERROR_NO_PERMISSION, 403 
            except:
                return ERROR_NO_PERMISSION, 403 
            # see if new instructor in request matches an instructor in db
            try:
                new_instructor = content['instructor_id']
                query = client.query(kind=USERS)
                query.add_filter('role', '=', INSTRUCTOR)
                instructors = list(query.fetch())
                course_instructor_exists = False
                for instructor in instructors:
                    if instructor.key.id == new_instructor:
                        course_instructor_exists = True
            # no isntructor in request
            except:
                course_instructor_exists = True
            # if invalid_content(content, COURSE_PROPERTIES):
            #     return (ERROR_BAD_REQUEST, 400)
            if course_instructor_exists == False:
                return (ERROR_BAD_REQUEST, 400)
            else:
                #post course
                course_update_dict = {}
                for property in COURSE_PROPERTIES:
                    try:
                        course_update_dict[property] = content[property]
                    except:
                        pass
                course_key = client.key(COURSES, course_id)
                course = client.get(key=course_key)
                course.update(course_update_dict)
                client.put(course)
                 # develop URL
                self_url = request.url
                # self_url = base_url + '/' + str(course_id)
                # return dict
                
                return ({
                    'id': course_id,
                    'instructor_id': course['instructor_id'],
                    'number': course['number'],
                    'subject': course['subject'],
                    'term': course['term'],
                    'title': course['title'],
                    'self': self_url
                    }, 200)
    else: 
        return jsonify(error='Method not recogonized')

# 11 - Delete a course
@app.route('/' + COURSES + '/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    """
    Protection: Admin only
    Description: Delete course and delete enrollment info about the course.
    """
    if request.method == 'DELETE':
        # content = request.get_json()
        # Error 400 if JWT missing
        # test if jwt valid - or return 401
        try:
            payload = verify_jwt(request)
        except:
            return ERROR_UNAUTHORIZED, 401
         # sub of requester
        request_sub = payload['sub']
        # get admin from datastore
        query = client.query(kind=USERS)
        query.add_filter('role', '=', ADMIN)
        admin = list(query.fetch())[0]
        
        if request_sub != admin['sub']:
            return ERROR_NO_PERMISSION, 403
        # elif client.get(COURSES, course_id) == None: 
        #     return ERROR_NO_PERMISSION, 403 
        else:
            # return 403 if course doesn't exist
            try:
                course_key = client.key(COURSES, course_id)
                course = client.get(key=course_key)
                if course == None:
                    return ERROR_NO_PERMISSION, 403 
            except:
                return ERROR_NO_PERMISSION, 403  
            # delete course 
            course_key = client.key(COURSES, course_id)    
            client.delete(course_key)
            # delete all enrollments associated with course
            enrollment_query = client.query(kind=ENROLLMENTS)
            enrollment_query.add_filter('course_id', '=', course_id)
            enrollments_in_course = list(enrollment_query.fetch())
            for enrollment in enrollments_in_course:
                client.delete(enrollment.key)
            return ('', 204)
    else: 
        return jsonify(error='Method not recogonized')

#---COURSES ENROLLMENT: Endpoints 12 to 13 ------------------------------------------------------------------------------------#

# 12 - Update enrollment in a course
@app.route('/' + COURSES + '/<int:course_id>' + '/students', methods=['PATCH'])
def udpate_course_enrollment(course_id):
    """
    Protection: Admin. Or instructors of the course
    Description: Enroll or disenroll students from the course
    """
    if request.method == 'PATCH':
        content = request.get_json()
        # Error 401 if JWT missing
        try:
            payload = verify_jwt(request)
        except:
            return ERROR_UNAUTHORIZED, 401
        # Error 403 if course doesn't exist or JWT doesn't belong to admin or course instructor
        # sub of requester
        request_sub = payload['sub']
        # get admin from datastore
        query = client.query(kind=USERS)
        query.add_filter('role', '=', ADMIN)
        admin = list(query.fetch())[0]
        # get instructor from datastore
        try:
            course_key = client.key(COURSES, course_id)
            course = client.get(key = course_key)
            if course == None:
                return ERROR_NO_PERMISSION, 403
        except:
            return ERROR_NO_PERMISSION, 403
        instructor_id = course['instructor_id']
        course_instructor_key = client.key(USERS, instructor_id)
        instructor = client.get(key=course_instructor_key)
        if request_sub != admin['sub'] and request_sub != instructor['sub']:
            return ERROR_NO_PERMISSION, 403
        else:
            # get all student id numbers
            query = client.query(kind=USERS)
            query.add_filter('role', '=', STUDENT)
            students = list(query.fetch())
            student_ids = []
            for student in students:
                student_ids.append(student.key.id)
            # check validity of enrollment data.
            add_enrollment_array = content['add']
            remove_enrollment_array = content['remove']
            for add_student in add_enrollment_array:
                if int(add_student) not in student_ids:
                    return ERROR_409, 409
                for remove_student in remove_enrollment_array:
                    if int(remove_student) not in student_ids:
                        return ERROR_409, 409
                    if add_student == remove_student:
                        return ERROR_409, 409
            # finally, start editing enrollment
            # first, get all students in course
            enrollment_query = client.query(kind=ENROLLMENTS)
            enrollment_query.add_filter('course_id', '=', course_id)
            enrollments_in_course = list(enrollment_query.fetch())
            student_ids_in_course = []
            for enrollment in enrollments_in_course:
                student_ids_in_course.append(enrollment['student_id'])

            # new Enrollment entity to track enrollment in course
            for student_id in add_enrollment_array:
                # check if student_id is already enrolled in course_id
                if student_id in student_ids_in_course:
                    pass # if already enrolled
                else:
                    # if not yet enrolled, enroll
                    new_enrollment = datastore.Entity(key=client.key(ENROLLMENTS))
                    new_enrollment.update({
                        'course_id': course_id,
                        'student_id': student_id
                    })
                    client.put(new_enrollment)
            # delete enrolled students
            for student_id in remove_enrollment_array:
                if int(student_id) not in student_ids_in_course:
                    pass # if not enrolled
                else:
                    # get key of enrollment
                    enrollment_query = client.query(kind=ENROLLMENTS)
                    enrollment_query.add_filter('course_id', '=', course_id)
                    enrollment_query.add_filter('student_id', '=', int(student_id))
                    enrollment = list(enrollment_query.fetch())[0]
                    # delete this enrollment record
                    enrollment_id = enrollment.key.id
                    enrollment_key = client.key(ENROLLMENTS, enrollment_id)
                    client.delete(enrollment_key)
            #return and update
            return '', 200
    else: 
        return jsonify(error='Method not recogonized')

# 13 - Get enrollment in a course
@app.route('/' + COURSES + '/<int:course_id>' + '/students', methods=['GET'])
def get_course_enrollment(course_id):
    """
    Protection: Admin. Or instructors of the course
    Description: All students enrolled in the course.
    """
    if request.method == 'GET':
        # content = request.get_json()
        # Error 401 if JWT missing
        try:
            payload = verify_jwt(request)
        except:
            return ERROR_UNAUTHORIZED, 401
        # Error 403 if course doesn't exist or JWT doesn't belong to admin or course instructor
        # sub of requester
        request_sub = payload['sub']
        # get admin from datastore
        query = client.query(kind=USERS)
        query.add_filter('role', '=', ADMIN)
        admin = list(query.fetch())[0]
        # 403 if the course doesn't exist
        try:
            course_key = client.key(COURSES, course_id)
            course = client.get(key = course_key)
            if course == None:
                return ERROR_NO_PERMISSION, 403
        except:
            return ERROR_NO_PERMISSION, 403
        # check if JWT belongs to course instructor or Admin
        instructor_id = course['instructor_id']
        course_instructor_key = client.key(USERS, instructor_id)
        instructor = client.get(key=course_instructor_key)
        if request_sub != admin['sub'] and request_sub != instructor['sub']:
            return ERROR_NO_PERMISSION, 403
        else:
            # finally, return get info
            # get key of enrollment
            enrollment_query = client.query(kind=ENROLLMENTS)
            enrollment_query.add_filter('course_id', '=', course_id)
            enrollment_for_course = list(enrollment_query.fetch())
            # convert list of dictionary items to list of student id's
            return_array = []
            for enrollment in enrollment_for_course:
                return_array.append(enrollment['student_id'])
            return return_array, 200
    else: 
        return jsonify(error='Method not recogonized')


#---JWT - GENERATE/DELETE ------------------------------------------------------------------------------------#

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        
# # Generate a JWT from the Auth0 domain and return it
# # Request: JSON body with 2 properties with "username" and "password"
# #       of a user registered with this Auth0 domain
# # Response: JSON with the JWT as the value of the property id_token
# @app.route('/login', methods=['POST'])
# def login_user():
#     content = request.get_json()
#     username = content["username"]
#     password = content["password"]
#     body = {'grant_type':'password','username':username,
#             'password':password,
#             'client_id':CLIENT_ID,
#             'client_secret':CLIENT_SECRET
#            }
#     headers = { 'content-type': 'application/json' }
#     url = 'https://' + DOMAIN + '/oauth/token'
#     r = requests.post(url, json=body, headers=headers)
#     return r.text, 200, {'Content-Type':'application/json'}

#--- HELPER FUNCTIONS------------------------------------------------------------------------------------#
def invalid_content(input, properties):
    input_properties =[]
    for i in input:
        input_properties.append(i)
    for property in properties:
        if property not in input_properties:
            return True
    return False

# def store_image():
#     # Any files in the request will be available in request.files object
#     # Check if there is an entry in request.files with the key 'file'
#     if 'file' not in request.files:
#         return ('No file sent in request', 400)
#     # Set file_obj to the file sent in the request
#     file_obj = request.files['file']
#     # If the multipart form data has a part with name 'tag', set the
#     # value of the variable 'tag' to the value of 'tag' in the request.
#     # Note we are not doing anything with the variable 'tag' in this
#     # example, however this illustrates how we can extract data from the
#     # multipart form data in addition to the files.
#     if 'tag' in request.form:
#         tag = request.form['tag']
#     # Create a storage client
#     storage_client = storage.Client()
#     # Get a handle on the bucket
#     bucket = storage_client.get_bucket(PHOTO_BUCKET)
#     # Create a blob object for the bucket with the name of the file
#     blob = bucket.blob(file_obj.filename)
#     # Position the file_obj to its beginning
#     file_obj.seek(0)
#     # Upload the file into Cloud Storage
#     blob.upload_from_file(file_obj)
#     return ({'file_name': file_obj.filename},201)

# def get_image(file_name):
#     storage_client = storage.Client()
#     bucket = storage_client.get_bucket(PHOTO_BUCKET)
#     # Create a blob with the given file name
#     blob = bucket.blob(file_name)
#     # Create a file object in memory using Python io package
#     file_obj = io.BytesIO()
#     # Download the file from Cloud Storage to the file_obj variable
#     blob.download_to_file(file_obj)
#     # Position the file_obj to its beginning
#     file_obj.seek(0)
#     # Send the object as a file in the response with the correct MIME type and file name
#     return send_file(file_obj, mimetype='image/x-png', download_name=file_name)

def delete_image(file_name):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_name)
    # Delete the file from Cloud Storage
    blob.delete()
    return '',204

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

