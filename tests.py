
from keri.core import coring
import uuid

from client import Client

def test_logout():

    client = Client("http://localhost:5000", coring.MtrDex.Ed25519)

    print(client.create_new_user("my_username" + str(uuid.uuid4()), "hunter2"))

    print(client.logout())

def test_delete():

    client = Client("http://localhost:5000", coring.MtrDex.Ed25519)

    print(client.create_new_user("my_username" + str(uuid.uuid4()), "hunter2"))

    print(client.delete())


def test_aid_verification():

    client = Client("http://localhost:5000", coring.MtrDex.Ed25519)

    print(client.create_new_user("my_username" + str(uuid.uuid4()), "hunter2"))

    print(client.verify_aid())

    print(client.delete())

def test_credential_issue():

    client = Client("http://localhost:5000", coring.MtrDex.Ed25519)

    print(client.create_new_user("my_username" + str(uuid.uuid4()), "hunter2"))

    print(client.verify_aid())

    print(client.register_credential_signing_keys())

    print(client.create_new_credential())

    print(client.get_credential())

    print(client.delete())