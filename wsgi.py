"""WSGI entrypoint: initialize database before accepting requests."""
from app import app, init
init()
