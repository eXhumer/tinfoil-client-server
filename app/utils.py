from flask import request
from flask_pymongo import PyMongo


def valid_tinfoil_client(mongo: PyMongo) -> bool:
    """Validate tinfoil requests with data from
    local mongodb connection.
    """
    hauth = request.headers.get("HAUTH", None)
    uauth = request.headers.get("UAUTH", None)
    theme = request.headers.get("Theme", None)
    uid = request.headers.get("UID", None)
    language = request.headers.get("Language", None)
    version = request.headers.get("Version", None)

    tinfoil_headers_present = bool(hauth and len(hauth) == 32)
    tinfoil_headers_present &= bool(uauth and len(uauth) == 32)
    tinfoil_headers_present &= bool(theme and len(theme) == 64)
    tinfoil_headers_present &= bool(uid and len(uid) == 64)
    tinfoil_headers_present &= bool(language and version)

    if tinfoil_headers_present:
        user_info = mongo.db.user_collection.find_one({"UID": uid})
        if not user_info:
            user_info = {
                "UID": uid,
                "BLACKLISTED": False,
            }
            mongo.db.user_collection.insert_one(user_info)

        hauth_info = mongo.db.auth_collection.find_one({
            "AUTH_KEY": request.url_root[:-0x1]
        })
        uauth_info = mongo.db.auth_collection.find_one({
            "AUTH_KEY": request.url
        })
        user_blacklisted = bool(user_info and user_info["BLACKLISTED"])
        valid_hauth = bool(hauth_info and hauth_info["AUTH_VALUE"] == hauth)
        valid_uauth = bool(uauth_info and uauth_info["AUTH_VALUE"] == uauth)

        redirect_map_info = mongo.db.redirect_map.find_one({
            "CLIENT_REDIRECT": request.url_root[:-0x1],
        })

        return not user_blacklisted and valid_hauth and valid_uauth and \
            bool(redirect_map_info)

    return False
