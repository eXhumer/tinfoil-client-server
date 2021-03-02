from flask import Flask
from flask_pymongo import PyMongo
from app.utils import valid_tinfoil_client
import json

app = Flask(__name__)
DB_HOST = "localhost"
DB_PORT = 27017
DB_NAME = "tinfoil_client_db"
app.config["MONGO_URI"] = f"mongodb://{DB_HOST}:{DB_PORT}/{DB_NAME}"
mongo = PyMongo(app)


@app.route("/")
def hello():
    if valid_tinfoil_client(mongo):
        return json.dumps({"success": "Loaded index successfully!"})

    return "<h1>Bad Request!</h1>", 400
