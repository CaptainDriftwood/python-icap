import io
import socket
from collections import UserDict
from http.client import HTTPResponse
from typing import Any
from typing import List
from pprint import pprint
from urllib import request, response


class NestedDict(UserDict):

    def deep_set(self, key: str, value: Any):
        # TODO Add keyword argument skip_if_exists
        keys = key.split(".")
        no_keys = len(keys)
        d = self.data
        for index, k in enumerate(keys, 1):
            if k in d:
                if isinstance(d[k], dict):
                    d = d[k]
            elif k not in d:
                if index != no_keys:
                    d[k] = dict()
                    d = d[k]
            if k in d and isinstance(k, dict):
                d = d[k]
            else:
                if index == no_keys:
                    d[k] = value

    def deep_get(self, key: str, **kwargs) -> Any:
        keys: List[str] = key.split(".")
        num_keys = len(keys)
        d = self.data
        for index, k in enumerate(keys, 1):
            try:
                d = d[k]
            except KeyError as e:
                if "default" in kwargs:
                    d[k] = dict()
                    if index == num_keys:
                        d[k] = kwargs["default"]
                else:
                    raise e
        return d

    def exists(self, key: str) -> bool:
        """Given a key, check if it exists in dictionary"""
        keys = key.split(".")
        num_keys = len(keys)
        d = self.data
        for index, k in enumerate(keys, 1):
            if k in d:
                d = d[k]
                if index == num_keys:
                    return True
        else:
            return False
