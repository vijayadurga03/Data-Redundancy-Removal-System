from flask import Flask, request, render_template,redirect, send_file,url_for,Response,session, send_from_directory,url_for,flash, jsonify,session
import os
import hashlib
import mysql.connector
from werkzeug.security import generate_password_hash
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from itsdangerous import URLSafeTimedSerializer 


app = Flask(__name__)
app.secret_key = "your_secret_key"  # Necessary for session handling
app.config['SECURITY_PASSWORD_SALT'] = 'your_salt'
UPLOAD_FOLDER = "uploaded_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Function to establish MySQL connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Ravi@132",
        database="user",
        auth_plugin="mysql_native_password"
    )
    
    
# Token generation function
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

# Function to send email
def send_reset_email(email, token):
    
    sender_email = "ravitharigoppula123@gmail.com"
    receiver_email = email
    # Use app-specific password for Gmail
    password = "srhk vndy gxzs ewzd" 

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = "Password Reset Request"

    body = f"Click the link to reset your password: http://127.0.0.1:5000/resetpassword/{token}"
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
    except Exception as e:
        print("Error:", e)


# Route to serve the login page
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            # Check if the username exists and matches the password
            query = "SELECT * FROM users WHERE username = %s AND password = %s"
            cursor.execute(query, (username, password))
            user = cursor.fetchone()

            if user:
                # Store user info in session
                session["username"] = user[1]  # Assuming the username is the second column in the database
                session["user_id"] = user[0]  # Assuming the ID is the first column in the database
                return redirect(url_for("homepage", show_message=True))
            else:
                
                flash("Invalid username or password. Please try again.", "error")

        except mysql.connector.Error as error:
            flash(f"Database error: {error}", "error")
            return redirect(url_for("login"))

        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()
    return render_template("login.html")



#route to forgot password
@app.route("/forgotpassword", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            

            # Check if the email exists in the database
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user:
                # Generate a token for password reset
                token = generate_reset_token(email)  # Your function to generate a token
                send_reset_email(email, token)  # Send the reset email

                # Update the user with the reset token
                cursor.execute("UPDATE users SET reset_token = %s WHERE email = %s", (token, email))
                connection.commit()

                flash("Password reset link has been sent to your email.", "success")

            else:
                flash("No account found with this email address.", "error")

        except mysql.connector.Error as error:
            flash(f"Database error: {error}", "error")
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    return render_template("forgotpassword.html")  # A simple form asking for the email


# Route to reset password (using the token)
@app.route("/resetpassword/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        # Verify the token and get the email
        serializer = URLSafeTimedSerializer(app.secret_key)
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600) # token valid for 1 hour
    except Exception as e:
        flash("The reset link is either invalid or has expired!", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form["new_password"]
        
        hashed_password = generate_password_hash(new_password)

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

                # Update the user's password
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
            connection.commit()

            flash("Your password has been reset successfully!", "success")
            return render_template("resetpassword.html", token=token)

        except mysql.connector.Error as error:
            flash(f"Database error: {error}", "error")
            return redirect(url_for("login"))

        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    return render_template("resetpassword.html", token=token)




# Route to serve the registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            # Check if the username or email already exists
            check_query = "SELECT * FROM users WHERE username = %s OR email = %s"
            cursor.execute(check_query, (username, email))
            existing_user = cursor.fetchone()

            if existing_user:
                flash("Username or Email already exists. Please login or use a different one.", "error")
                return redirect(url_for("register"))

            # Insert data into users table
            insert_query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
            cursor.execute(insert_query, (username, email, password))
            connection.commit()

            flash("Registration successful! Please login.", "success")
            return render_template("register.html")

        except mysql.connector.Error as error:
            flash(f"Database error: {error}", "error")
            return redirect(url_for("register"))

        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()
    return render_template("register.html")

# Route to serve the home page (after successful login)
@app.route("/homepage")
def homepage():
    if "username" not in session:
        flash("You need to log in first!", "error")
        return redirect(url_for("login"))
    
    username = session["username"]
    return render_template("homepage.html", username=username)

# Route to handle file uploads
@app.route("/uploadfiles", methods=["GET", "POST"])
def uploadfiles():
    if "username" not in session:  # Check if the user is logged in
        flash("You need to log in first!", "error")
        return redirect(url_for("login"))  # Redirect to login if not logged in

    if request.method == "POST":
        # Check if a file is part of the request
        if "file" not in request.files:
            flash("No file part", "error")
            return redirect(request.url)

        file = request.files["file"]

        # If user does not select a file
        if file.filename == "":
            flash("No selected file", "error")
            return redirect(request.url)

        if file:
            # Calculate the SHA-256 hash for the file
            file_hash = hashlib.sha256(file.read()).hexdigest()
            file.seek(0)  # Go back to the start of the file to save it

            try:
                connection = get_db_connection()
                cursor = connection.cursor()

                # Check if the file content already exists in the 'files' table
                check_query = "SELECT id FROM files WHERE filehash = %s"
                cursor.execute(check_query, (file_hash,))
                file_entry = cursor.fetchone()

                if not file_entry:
                    # Save the file
                    file_extension = os.path.splitext(file.filename)[1]
                    file_path = os.path.join("uploaded_files", file_hash + file_extension)
                    file.save(file_path)

                    # Insert the file into the database
                    insert_file_query = "INSERT INTO files (filehash, filepath) VALUES (%s, %s)"
                    cursor.execute(insert_file_query, (file_hash, file_path))
                    connection.commit()  # Commit changes to the database
                    file_id = cursor.lastrowid  # Get the ID of the inserted file
                    flash("File uploaded successfully!", "success")

                else:
                    # File content already exists, reference the existing file
                    file_id = file_entry[0]
                    flash("Duplicate file found, but successfully linked!", "warning")

                # Check if user already uploaded the file
                check_user_file_query = "SELECT * FROM user_files WHERE user_id = %s AND file_id = %s"
                cursor.execute(check_user_file_query, (session["user_id"], file_id))
                existing_user_file = cursor.fetchone()
                
                if not existing_user_file:
                    # Now associate the file with the user
                    insert_user_file_query = "INSERT INTO user_files (user_id, file_id, filename) VALUES (%s, %s, %s)"
                    cursor.execute(insert_user_file_query, (session["user_id"], file_id, file.filename))
                    connection.commit()

                else:
                    flash("You have already uploaded this file!", "info")

            except mysql.connector.Error as error:
                flash(f"Database error: {error}", "error")
                return redirect(request.url)

            finally:
                if cursor:
                    cursor.close()
                if connection and connection.is_connected():
                    connection.close()

    return render_template("uploadfiles.html")



@app.route("/duplicate_and_original_files")
def duplicate_and_original_files():
    # Debug: Log session check
    print("Session:", session)

    # Ensure the user is logged in
    if "username" not in session:
        flash("You need to log in first!", "error")
        print("Redirecting to login because session is missing.")  # Debug
        return redirect(url_for("login"))

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Query to get original and duplicate files uploaded by the current user
        query = """
                SELECT 
                    f1.id AS original_id, 
                    f1.filepath AS original_filepath,
                    uf1.filename AS original_filename,
                    f2.id AS duplicate_id, 
                    f2.filepath AS duplicate_filepath,
                    uf2.filename AS duplicate_filename
                FROM file_duplicates fd
                JOIN files f1 ON fd.original_file_id = f1.id
                JOIN files f2 ON fd.duplicate_file_id = f2.id
                JOIN user_files uf1 ON uf1.file_id = f1.id
                JOIN user_files uf2 ON uf2.file_id = f2.id
                WHERE uf1.user_id = %s AND uf2.user_id = %s;
            """

        cursor.execute(query, (session["user_id"], session["user_id"]))
        file_pairs = cursor.fetchall()

        # Debug: Log query result
        print(f"Found {len(file_pairs)} duplicate pairs.")  # Debug

        return render_template("duplicate_and_original_files.html", file_pairs=file_pairs, username=session["username"])

    except mysql.connector.Error as error:
        flash(f"Database error: {error}", "error")
        print(f"Database error: {error}")  # Debug
        return redirect(url_for("homepage"))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()



@app.route("/myfiles", methods=["GET", "POST"])
def myfiles():
    if "username" not in session:
        flash("You need to log in first!", "error")
        return redirect(url_for("login"))

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)  # Fetch rows as dictionaries

        # Fetch files for the logged-in user
        query = "SELECT files.id, user_files.filename FROM files JOIN user_files ON files.id = user_files.file_id WHERE user_files.user_id = %s"
        cursor.execute(query, (session['user_id'],))
        files = cursor.fetchall()

        return render_template('myfiles.html', files=files)

    except Exception as e:
        flash(f"An error occurred: {e}", "error")
        return redirect(url_for("homepage"))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# Route to handle file download
@app.route("/download/<int:file_id>", methods=["GET"])
def download_file(file_id):
    if "username" not in session:
        flash("You need to log in first!", "error")
        return redirect(url_for("login"))

    try:
        print(f"Starting download process for file ID: {file_id}")  # Debugging
        connection = get_db_connection()
        cursor = connection.cursor()

        # Fetch file info from the database
        query = "SELECT filepath FROM files WHERE id = %s"
        cursor.execute(query, (file_id,))
        file_info = cursor.fetchone()

        if file_info:
            # Extract the file path
            file_path = file_info[0]
            print(f"Fetched file path: {file_path}")  # Debugging

            # Convert to absolute path
            file_path = os.path.abspath(file_path.replace('\\', '/'))
            file_path = os.path.join(os.getcwd(), file_path)
            print(f"Final file path: {file_path}")  # Debugging

            # Check if the file exists
            if os.path.exists(file_path):
                print("File exists, preparing to send file.")
                # Return the file directly
                return send_file(file_path, as_attachment=True)
            else:
                flash("File not found on the server.", "error")
                print(f"File not found: {file_path}")  # Debugging
        else:
            flash("Invalid file ID.", "error")
            print(f"Invalid file ID: {file_id}")  # Debugging

    except mysql.connector.Error as error:
        flash(f"Database error: {error}", "error")
        print(f"Database error: {error}")  # Debugging
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", "error")
        print(f"Unexpected error: {e}")  # Debugging

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

    # Return to the files page if anything fails
    return redirect(url_for("myfiles"))

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if "username" not in session:
        flash("You need to log in first!", "error")
        return redirect(url_for("login"))

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Fetch file details to verify ownership and get the path
        query = "SELECT files.filepath, files.hash FROM files JOIN user_files ON files.id = user_files.file_id WHERE user_files.file_id = %s AND user_files.user_id = %s"
        
        cursor.execute(query, (file_id, session["user_id"]))
        file = cursor.fetchone()

        if file:
            file_path = file[0]
            file_hash = file[1]
            print(f"File path found: {file_path}, File hash: {file_hash}")  # Debugging statement

            # Delete the file record from `user_files`
            delete_user_file_query = "DELETE FROM user_files WHERE file_id = %s AND user_id = %s"
            cursor.execute(delete_user_file_query, (file_id, session["user_id"]))
            connection.commit()

            # Check how many users are still linked to this file
            cursor.execute("SELECT COUNT(*) FROM user_files WHERE file_id = %s", (file_id,))
            user_count = cursor.fetchone()[0]

            # If no more users are linked, delete the file from `files` table and disk
            if user_count == 0:
                cursor.execute("DELETE FROM files WHERE id = %s", (file_id,))
                connection.commit()

                # Remove file from disk if exists
                if os.path.exists(file_path):
                    os.remove(file_path)  # Delete from disk
                    print(f"File {file_path} removed from disk.")  # Debugging statement
                else:
                    print(f"File {file_path} not found on disk.")  # Debugging statement

                # Check if the hash value should be deleted if no other references exist
                cursor.execute("SELECT COUNT(*) FROM files WHERE hash = %s", (file_hash,))
                if cursor.fetchone()[0] == 0:
                    # If no other file has this hash, remove the hash from the database
                    cursor.execute("DELETE FROM file_hashes WHERE hash = %s", (file_hash,))
                    connection.commit()
                    print(f"Hash {file_hash} removed from database.")  # Debugging statement

            flash("File deleted successfully!", "success")
        else:
            flash("File not found or you don't have permission to delete it.", "error")

    except mysql.connector.Error as error:
        flash(f"Database error: {error}", "error")
    except Exception as e:
        flash(f"Unexpected error: {e}", "error")
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

    return redirect(url_for("myfiles"))

@app.route("/view/<int:file_id>")
def view_file(file_id):
    # Check if the user is logged in
    if "username" not in session:
        flash("You need to log in first!", "error")
        return redirect(url_for("login"))

    try:
        # Establish a database connection
        connection = get_db_connection()
        cursor = connection.cursor()

        # Fetch the file details from the database using the provided file ID
        query = "SELECT filepath FROM files WHERE id = %s"
        cursor.execute(query, (file_id,))
        file = cursor.fetchone()

        if file:
            file_path = file[0]

            # Check if the file exists on the server
            if os.path.exists(file_path):
                # If the file exists, open it in a new tab (e.g., image, PDF)
                return send_from_directory(os.path.dirname(file_path), os.path.basename(file_path))
            else:
                flash("File not found on the server", "error")
                return redirect(url_for("myfiles"))
        else:
            flash("File does not exist in the database", "error")
            return redirect(url_for("myfiles"))

    except mysql.connector.Error as error:
        flash(f"Database error: {error}", "error")
        return redirect(url_for("myfiles"))

    finally:
        # Close the database cursor and connection
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# Route to log out
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)

