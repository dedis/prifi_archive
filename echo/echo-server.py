from bottle import request, route, run
import json

@route("/echo", method="POST")
def echo():
    text = request.json["text"]
    return {"text" : text}

run(port=8080)
