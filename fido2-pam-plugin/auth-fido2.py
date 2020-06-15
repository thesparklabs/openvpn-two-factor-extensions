#!/usr/bin/python
# Copyright (C) 2018 SparkLabs Pty Ltd
#
# This file is part of OpenVPN FIDO2 Server Support.
#
# OpenVPN FIDO2 Server Support is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# OpenVPN FIDO2 Server Support is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenVPN FIDO2 Server Support.  If not, see <http://www.gnu.org/licenses/>.

import sys, os, base64
import json, zlib
import pickle

def base64encode(string: str):
    return base64.b64encode(string.encode('utf-8')).decode('utf-8')

def base64decode(string: str):
    return base64.b64decode(string.encode('utf-8')).decode('utf-8')

from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.client import ClientData
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.rpid import suffixes
from fido2 import cbor
import six
from six.moves.urllib.parse import urlparse

# Based on https://github.com/Yubico/python-fido2/blob/master/fido2/rpid.py
def verify_rp_id_openvpn(rp_id, origin):
    """Checks if a Webauthn RP ID is usable for a given origin.
    :param rp_id: The RP ID to validate.
    :param origin: The origin of the request.
    :return: True if the RP ID is usable by the origin, False if not.
    """
    if isinstance(rp_id, six.binary_type):
        rp_id = rp_id.decode()
    if not rp_id:
        return False
    if isinstance(origin, six.binary_type):
        origin = origin.decode()

    url = urlparse(origin)
    if url.scheme != "openvpn":
        return False
    host = url.hostname
    if host == rp_id:
        return True
    if host.endswith("." + rp_id) and rp_id not in suffixes:
        return True
    return False

def verify_origin_for_rp_openvpn(rp_id):
    return lambda o: verify_rp_id_openvpn(rp_id, o)


class OpenVPNFIDO2AuthPlugin:
    def __init__(self, fido2Origin, fido2Name):
        rp = PublicKeyCredentialRpEntity(fido2Origin, fido2Name)
        self.server = Fido2Server(rp, verify_origin=verify_origin_for_rp_openvpn)
        self.credentials = {}
        self.credsfile = 'creds.pickle'
        self.loadCredentials(self.credsfile)

    def loadCredentials(self, path):
        if os.path.exists(path):
            with open(path, 'r') as fp:
                for line in fp:
                    kvp = line.strip().split(' ')
                    if len(kvp) != 2:
                        continue
                    self.credentials[kvp[0]] = pickle.loads(base64.b64decode(kvp[1].encode('utf-8')))

    def saveCredentials(self, path):
        with open(path, 'w') as fp:
            for username, data in self.credentials.items():
                fp.write('{0} {1}\n'.format(username, base64.b64encode(pickle.dumps(data)).decode('utf-8')))

    def Run(self):
        username = os.environ.get('username')
        password = os.environ.get('password')

        if username == None:
            print("No username issued")
            exit(1)

        if password == None:
            # Request for reg or auth
            if self.userNeedsRegistration(username):
                #Send a registration request
                reply = self.buildFIDO2Registration(username)
                if reply == None:
                    exit(1)
                print(reply)
            else:
                reply = self.buildFIDO2Auth(username)
                if reply == None:
                    exit(1)
                print(reply)
            exit(2)

        elif password.startswith('CRV1:'):
            #Finish
            passwordSplit = password.split('::')
            ident = passwordSplit[1]
            token = base64.b64decode(passwordSplit[2].encode('utf-8'))
            #check if our token data is compressed
            if token.startswith(b'\x1f\x8b'):
                #Data is compressed, inflate
                try:
                    token = zlib.decompress(token, 47)
                except:
                    pass #Try without decompressing                    

            #Check if register or auth
            if ident == "reg":
                success = self.finishFIDO2Registration(username, token)
                if success:
                    #Now Auth
                    reply = self.buildFIDO2Auth(username)
                    if reply == None:
                        exit(1)
                    print(reply)
                    exit(2)
            else:
                success = self.finishFIDO2Auth(username, token)
                if success:
                    #Let the user connect
                    exit(0)

        exit(1)

    def userNeedsRegistration(self, user):
        if user in self.credentials and len(self.credentials[user]["credentials"]) > 0:
            return False
        return True

    def buildFIDO2Registration(self, user):
        try:
            self.credentials[user] = {}
            self.credentials[user]["credentials"] = []
            registration_data, state = self.server.register_begin(
                {
                    "id": user.encode('utf-8'), #Required
                    "name": user, # Optional
                    #"displayName": "First Last", #Optional
                    #"icon": "https://domain.com/user_avatar.png" #Optional
                },
                self.credentials[user]["credentials"],
                # User Verification Mode
                # discouraged - passwordless devices can be used, required - User password required for device to be used, 
                # preferred - User password not required but preferred
                # Note - Windows will still require a PIN be created for devices that support it if using 'preferred'
                user_verification="discouraged",

                # Supported Authenticator Types
                # cross-platform - e.g. usb yubikey, platform - e.g. Windows Hello, omit/None - Any type
                # If using USB tokens like Yubikeys, it's recommended cross-platform is set, Windows Hello will prompt before a Yubikey
                #authenticator_attachment="cross-platform", 
            )

            self.credentials[user]["state"] = state
            ec_data = cbor.encode(registration_data)
            b64reg = base64.b64encode(ec_data).decode('utf-8')
            b64user = base64encode(user)
            reply = "CRV1:FIDO2,R:reg:%s:%s" % (b64user, b64reg)
            self.saveCredentials(self.credsfile)
            return reply
        except Exception as e:
            print("Failed buildFIDO2Registration")
            print(e)
        return None

    def finishFIDO2Registration(self, user, reply):
        try:
            state = self.credentials[user]["state"]
            data = cbor.decode(reply)
            client_data = ClientData(data["clientDataJSON"].encode('utf-8'))
            att_obj = AttestationObject(data["attestationObject"])
            
            auth_data = self.server.register_complete(state, client_data, att_obj)
            self.credentials[user]["credentials"].append(auth_data.credential_data)
            self.saveCredentials(self.credsfile)
            return True
        except Exception as e:
            print("Failed finishFIDO2Registration")
            print(e)
        return False

    def buildFIDO2Auth(self, user):
        if user not in self.credentials:
            return None
        try:
            auth_data, state = self.server.authenticate_begin(self.credentials[user]["credentials"])
            self.credentials[user]["state"] = state
            ec_data = cbor.encode(auth_data)
            b64auth = base64.b64encode(ec_data).decode('utf-8')
            b64user = base64encode(user)
            reply = "CRV1:FIDO2:auth:%s:%s" % (b64user, b64auth)
            self.saveCredentials(self.credsfile)
            return reply
        except Exception as e:
            print("Failed buildFIDO2uth")
            print(e)
        return None

    def finishFIDO2Auth(self, user, reply):
        if user not in self.credentials:
            return None
        try:
            state = self.credentials[user]["state"]
            data = cbor.decode(reply)
            credential_id = data["credentialId"]
            client_data = ClientData(data["clientDataJSON"].encode('utf-8'))
            auth_data = AuthenticatorData(data["authenticatorData"])
            signature = data["signature"]

            self.server.authenticate_complete(
                state,
                self.credentials[user]["credentials"],
                credential_id,
                client_data,
                auth_data,
                signature,
            )
            return True
        except Exception as e:
            print("Failed finishFIDO2Auth")
            print(e)
        return False

if __name__ == '__main__':
    origin = os.environ.get('fido2_origin')
    if not origin:
        print("FIDO2 Origin not set")
        exit(1)
    name = os.environ.get('fido2_name')
    if not name:
        print("FIDO2 Name not set")
        exit(1)
    #origin = "myserver.domain.com"
    #name = "My OpenVPN Server"
    authClient = OpenVPNFIDO2AuthPlugin(origin, name)
    authClient.Run()