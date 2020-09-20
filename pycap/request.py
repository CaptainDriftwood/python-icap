import io
import socket
from http.client import HTTPResponse
from urllib import request, response


class Request:

    def __init__(self):
        pass


if __name__ == '__main__':
    req: HTTPResponse = request.urlopen("https://www.google.com")
    print(req)
    # A test comment

    # Another test comment

    # A final test comment
