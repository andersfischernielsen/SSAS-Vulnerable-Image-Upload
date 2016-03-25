from flask import Flask, render_template, request, abort, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from os import getcwd

app = Flask(__name__)


@app.route('/')
def hello():
    return render_template('index.html')


@app.route('/upload_image', methods=['POST'])
def login():
    pic = request.files["image_upload"]
    filename = secure_filename(pic.filename)
    pic.save("/Users/Anders/Desktop/" + filename)
    return redirect(url_for('uploaded_file', filename=filename))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory("/Users/Anders/Desktop/", filename)


if __name__ == '__main__':
    app.debug = True
    app.run()
