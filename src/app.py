import os
import sqlite3
import csv
import io
import random
import datetime
from functools import wraps
import pytz

from flask import (
    Flask, request, jsonify, g, render_template,
    send_file, make_response, Response, flash, redirect, url_for
)

# --- Configuration ---

app = Flask(__name__)
app.secret_key = os.urandom(24)

API_KEY = os.getenv("API_KEY")
DATABASE_PATH = os.getenv("DB_PATH", "activation_data.db")
TIMEZONE = pytz.timezone('America/Lima')

# --- Key Status Constants ---

STATUS_AVAILABLE = 'AVAILABLE'
STATUS_PENDING = 'PENDING'
STATUS_ACTIVATED = 'ACTIVATED'
STATUS_FAILED = 'FAILED'
VALID_FINAL_STATUSES = {STATUS_ACTIVATED, STATUS_FAILED}

if not API_KEY:
    raise ValueError("No API_KEY set for Flask application.")

# --- Database Helper Functions (get_db, close_db, init_db, init_db_command remain the same) ---

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    print("Initialized the database.")

@app.cli.command('init-db')
def init_db_command():
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        with app.open_resource('schema.sql', mode='r') as f:
            conn.cursor().executescript(f.read())
        conn.commit()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {e}")
    finally:
        conn.close()

# --- Authentication Decorators (require_api_key, require_basic_auth remain the same) ---

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authorization header missing or invalid"}), 401
        token = auth_header.split(' ')[1]
        if token != API_KEY:
            return jsonify({"error": "Invalid API Key"}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_basic_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username and auth.password):
            return Response(
                'Could not verify your access level for that URL.\n'
                'You have to login with proper credentials', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'})
        if auth.password != API_KEY:
            return Response('Invalid credentials', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Functions ---

def get_current_lima_time():
    utc_now = datetime.datetime.now(pytz.utc)
    lima_now = utc_now.astimezone(TIMEZONE)
    return lima_now.isoformat()

# --- API Endpoints ---

@app.route('/activate', methods=['POST'])
@require_api_key
def activate_windows():
    """
    Retrieves an AVAILABLE activation key, marks it as PENDING, and logs the attempt.
    Expects JSON: {"serial_number": "YOUR_PC_SERIAL"}
    Returns JSON: {"activation_key": "SELECTED_KEY"} or error.
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    serial_number = data.get('serial_number')

    if not serial_number:
        return jsonify({"error": "Missing 'serial_number' in request body"}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # Find a random available key
        cursor.execute(
            "SELECT key FROM keys WHERE status = ? ORDER BY RANDOM() LIMIT 1",
            (STATUS_AVAILABLE,)
        )
        key_row = cursor.fetchone()

        if not key_row:
            app.logger.warning(f"No available activation keys for serial: {serial_number}")
            return jsonify({"error": "No available activation keys found"}), 503

        selected_key = key_row['key']
        current_time = get_current_lima_time()

        # Mark key as PENDING
        cursor.execute(
            "UPDATE keys SET status = ? WHERE key = ?",
            (STATUS_PENDING, selected_key)
        )

        # Log the activation *attempt* (key retrieval)
        cursor.execute(
            "INSERT INTO activations (serial_number, key_used, activation_time) VALUES (?, ?, ?)",
            (serial_number, selected_key, current_time)
        )

        db.commit() # Commit changes

        app.logger.info(f"Issued key '{selected_key}' (PENDING) to Serial '{serial_number}' at {current_time}")
        return jsonify({"activation_key": selected_key}), 200

    except sqlite3.Error as e:
        db.rollback()
        app.logger.error(f"Database error during key issuance for serial {serial_number}: {e}")
        return jsonify({"error": "Internal server error during key issuance"}), 500
    except Exception as e:
        db.rollback()
        app.logger.error(f"Unexpected error during key issuance for serial {serial_number}: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/report_status', methods=['POST'])
@require_api_key
def report_activation_status():
    """
    Endpoint for PowerShell script to report the final status of an activation attempt.
    Expects JSON: {"key": "ACTIVATION_KEY", "status": "ACTIVATED|FAILED", "serial_number": "PC_SERIAL"}
    Updates the key status from PENDING to the reported status.
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    key = data.get('key')
    reported_status = data.get('status')
    serial_number = data.get('serial_number') # Good for logging context

    if not key or not reported_status or not serial_number:
        return jsonify({"error": "Missing 'key', 'status', or 'serial_number' in request body"}), 400

    if reported_status not in VALID_FINAL_STATUSES:
        return jsonify({"error": f"Invalid status provided. Must be one of: {', '.join(VALID_FINAL_STATUSES)}"}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # Check current status - we should only update if it's PENDING
        cursor.execute("SELECT status FROM keys WHERE key = ?", (key,))
        key_row = cursor.fetchone()

        if not key_row:
            app.logger.warning(f"Status report received for unknown key: {key} (Serial: {serial_number}, Status: {reported_status})")
            return jsonify({"error": "Key not found"}), 404

        current_status = key_row['status']

        if current_status != STATUS_PENDING:
            # Log this potentially odd situation but don't change the status
            # It might be a late report after another process already updated it,
            # or an attempt to report status on an already available/failed/activated key.
            app.logger.warning(f"Received status report for key '{key}' (Serial: {serial_number}) but its current status is '{current_status}', not PENDING. No update performed.")
            return jsonify({"message": f"Key status is already '{current_status}'. No update performed."}), 200 # Or maybe 409 Conflict? 200 seems gentler.

        # Update the key status
        cursor.execute("UPDATE keys SET status = ? WHERE key = ?", (reported_status, key))
        db.commit()

        app.logger.info(f"Updated status for key '{key}' (Serial: {serial_number}) from PENDING to {reported_status}")
        return jsonify({"message": "Activation status updated successfully"}), 200

    except sqlite3.Error as e:
        db.rollback()
        app.logger.error(f"Database error updating status for key {key} (Serial: {serial_number}): {e}")
        return jsonify({"error": "Internal server error during status update"}), 500
    except Exception as e:
        db.rollback()
        app.logger.error(f"Unexpected error updating status for key {key} (Serial: {serial_number}): {e}")
        return jsonify({"error": "An unexpected error occurred during status update"}), 500

@app.route('/upload', methods=['GET'])
def upload_form():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def handle_upload():
    submitted_api_key = request.form.get('api_key')
    if not submitted_api_key or submitted_api_key != API_KEY:
        flash('Invalid API Key provided.', 'error')
        return redirect(url_for('upload_form'))

    if 'keyfile' not in request.files:
        flash('No file part in the request.', 'error')
        return redirect(url_for('upload_form'))

    file = request.files['keyfile']
    if file.filename == '':
        flash('No file selected for uploading.', 'error')
        return redirect(url_for('upload_form'))

    if file and file.filename.endswith('.csv'):
        db = get_db() # Get db connection here to manage transaction
        try:
            stream = io.StringIO(file.stream.read().decode("UTF-8"), newline=None)
            csv_reader = csv.reader(stream)
            cursor = db.cursor()
            added_count = 0
            skipped_count = 0

            for row in csv_reader:
                if not row: continue
                key = row[0].strip()
                if not key: continue
                try:
                    # The schema now sets DEFAULT 'AVAILABLE'
                    cursor.execute("INSERT OR IGNORE INTO keys (key) VALUES (?)", (key,))
                    if cursor.rowcount > 0:
                        added_count += 1
                    else:
                        skipped_count +=1
                except sqlite3.Error as db_err:
                    flash(f"Database error while processing key '{key}': {db_err}", "error")
                    skipped_count += 1 # Count as skipped on specific DB error

            db.commit() # Commit all inserts at the end
            flash(f"Successfully processed file. Added: {added_count} new keys (status: AVAILABLE). Skipped/Duplicates: {skipped_count} keys.", 'success')
            app.logger.info(f"Key upload successful. Added: {added_count}, Skipped: {skipped_count}")

        except Exception as e:
            db.rollback() # Rollback if any error occurred during file processing
            flash(f"An error occurred processing the file: {e}", 'error')
            app.logger.error(f"Error during key upload: {e}")
        finally:
             pass # StringIO doesn't need explicit close

        return redirect(url_for('upload_form'))
    else:
        flash('Invalid file type. Please upload a .csv file.', 'error')
        return redirect(url_for('upload_form'))

@app.route('/download/activations', methods=['GET'])
@require_basic_auth # Use Basic Auth for browser prompt
def download_activations():
    """
    Provides a detailed activation log as a CSV file download,
    joining activation attempts with the final key status.
    """
    try:
        db = get_db()
        cursor = db.cursor()

        # --- Updated SQL Query ---
        # Join activations with keys to get the status associated with the key used
        query = """
            SELECT
                a.serial_number,
                a.key_used,
                a.activation_time,
                k.status
            FROM
                activations a
            INNER JOIN
                keys k ON a.key_used = k.key
            ORDER BY
                a.activation_time DESC
        """
        cursor.execute(query)
        activation_details = cursor.fetchall() # Fetch all results from the JOIN

        # Use io.StringIO to create CSV in memory
        si = io.StringIO()
        cw = csv.writer(si)

        # --- Updated CSV Header ---
        cw.writerow(['Serial Number', 'Key Used', 'Retrieval Time (America/Lima)', 'Final Key Status'])

        # --- Updated Data Row Writing ---
        if activation_details:
             # Access columns by name thanks to row_factory=sqlite3.Row
             cw.writerows([
                 (row['serial_number'], row['key_used'], row['activation_time'], row['status'])
                 for row in activation_details
             ])
        else:
             # Message if no activation attempts have been logged yet
             cw.writerow(['No activation attempt records found.', '', '', '']) # Add empty cells for alignment

        # Prepare response
        output = make_response(si.getvalue())
        # --- Optionally update filename ---
        output.headers["Content-Disposition"] = "attachment; filename=activation_details_log.csv"
        output.headers["Content-type"] = "text/csv"
        app.logger.info("Activation details log downloaded.") # Updated log message
        return output

    except sqlite3.Error as e:
        app.logger.error(f"Database error during activation details log download: {e}")
        return jsonify({"error": "Failed to retrieve activation details from database."}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during activation details log download: {e}")
        return jsonify({"error": "An unexpected error occurred while generating the report."}), 500

@app.route('/')
@require_basic_auth # Protect this page with the same auth as the download
def view_activation_log():
    """Displays the activation log details in an HTML table."""
    logs = [] # Initialize empty list
    error_message = None
    try:
        db = get_db()
        cursor = db.cursor()
        # Use the same JOIN query as the download endpoint
        query = """
            SELECT
                a.serial_number,
                a.key_used,
                a.activation_time,
                k.status
            FROM
                activations a
            INNER JOIN
                keys k ON a.key_used = k.key
            ORDER BY
                a.activation_time DESC
        """
        cursor.execute(query)
        logs = cursor.fetchall() # Fetch all results

    except sqlite3.Error as e:
        app.logger.error(f"Database error viewing activation log: {e}")
        # Set an error message to display on the page (or render a dedicated error template)
        error_message = "Error retrieving activation log data from the database."
        # Optional: flash(error_message, 'error') # If you prefer flashed messages
    except Exception as e:
        app.logger.error(f"Unexpected error viewing activation log: {e}")
        error_message = "An unexpected error occurred while retrieving the activation log."
        # Optional: flash(error_message, 'error')

    # Render the HTML template, passing the fetched logs (or empty list) and any error
    return render_template('log.html', logs=logs, error=error_message)

#@app.route('/')
#def index():
#    api_key_status = "Set" if API_KEY else "Not Set (CRITICAL)"
#    return f"<h1>Windows Activation Server</h1><p>API Key Status: {api_key_status}</p><p>DB Path: {DATABASE_PATH}</p><p><a href='/upload'>Upload Keys</a></p>"

if __name__ == '__main__':
    if not os.path.exists(DATABASE_PATH):
        print(f"Database file not found at {DATABASE_PATH}. Initializing...")
        with app.app_context():
             init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)

