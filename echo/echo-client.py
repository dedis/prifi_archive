import json
import requests

d = {"text" : "just testing a simple echo server"}
resp = requests.post("http://localhost:8080/echo",
                    headers={"content-type" : "application/json"},
                    data=json.dumps(d)).json()
print(resp["text"])
