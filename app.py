from flask import Flask, jsonify, request, render template string
import threading, sys, os
sys.path.insert(0, os.path.dirname(file))
from dns_server import shared, lock, cache, blocklist, rules, start as start dns
app = Flask(name)
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device width,initial scale=1">
<title>NBASecurity DNS</title>
<style>
