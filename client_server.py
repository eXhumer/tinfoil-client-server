from flask import Flask
from flask_pymongo import PyMongo
from app.utils import valid_tinfoil_client
import json

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/tinfoil_client_db"
mongo = PyMongo(app)


@app.route("/")
def hello():
    if valid_tinfoil_client(mongo):
        return json.dumps({"success": "Loaded index successfully!"})

    return "<h1>Bad Request!</h1>", 400
