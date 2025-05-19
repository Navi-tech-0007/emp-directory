import boto3
import hashlib
import os
import binascii

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = binascii.unhexlify(salt)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(pwd_hash).decode('utf-8'), binascii.hexlify(salt).decode('utf-8')

def add_user(email, password, salt, name=None, hrcode=None, role="user", object_key=None):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    item = {
        'username': email,
        'password': password,
        'salt': salt,
        'name': name,
        'hrcode': hrcode,
        'role': role,
        'active': True
    }
    if object_key:
        item['object_key'] = object_key
    table.put_item(Item=item)

def get_user(username):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    resp = table.get_item(Key={'username': username})
    return resp.get('Item')