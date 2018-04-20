#!/usr/bin/python
# Copyright (C) 2018 SparkLabs Pty Ltd
#
# This file is part of OpenVPN U2F Server Support.
#
# OpenVPN U2F Server Support is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# OpenVPN U2F Server Support is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenVPN U2F Server Support.  If not, see <http://www.gnu.org/licenses/>.

import sys, os
import json, zlib
from base64 import b64decode, b64encode

from u2fval_client.client import (
    Client,
)
from u2fval_client.exc import (
    BadAuthException,
    BadInputException,
    ServerUnreachableException,
    InvalidResponseException,
    U2fValClientException,
)

class OpenVPNU2FAuthPlugin:
    def __init__(self, u2fvalAddress):
        self.u2fClient = Client(u2fvalAddress)

    def Run(self):
        username = os.environ.get('username')
        password = os.environ.get('password')

        if username == None:
            print "No username issued"
            exit(1)

        if password == None:
            # Request for reg or auth
            if self.userNeedsRegistration(username):
                #Send a registration request
                reply = self.buildU2FRegistration(username)
                if reply == None:
                    exit(1)
                print reply
            else:
                reply = self.buildU2FAuth(username)
                if reply == None:
                    exit(1)
                print reply
            exit(2)

        elif password.startswith('CRV1:'):
            #Finish
            passwordSplit = password.split('::')
            ident = passwordSplit[1]
            token = b64decode(passwordSplit[2])
            #check if our token data is compressed
            if token.startswith(b'\x1f\x8b'):
                #Data is compressed, inflate
                try:
                    token = zlib.decompress(token, 47)
                except:
                    pass #Try without decompressing                    

            #Check if register or auth
            response = json.loads(str(token))
            if "registrationData" in response:
                #Adds required version field...
                response["version"] = "U2F_V2"
                success = self.finishU2FRegistration(username, json.dumps(response))
                if success:
                    #Now Auth
                    reply = self.buildU2FAuth(username)
                    if reply == None:
                        exit(1)
                    print reply
                    exit(2)
            else:
                success = self.finishU2FAuth(username, json.dumps(response))
                if success:
                    #Let the user connect
                    exit(0)

        exit(1)

    def userNeedsRegistration(self, user):
        data = self.u2fClient.list_devices(user)
        return len(data) < 1

    def buildU2FRegistration(self, user):
        try:
            data = self.u2fClient.register_begin(user)
            regreqs = data["registerRequests"]
            regreq = regreqs[0]
            #Get the appid from data and add
            regreq["appId"] = data["appId"]
            regstr = json.dumps(regreq)

            b64reg = b64encode(regstr)
            b64user = b64encode(user)

            reply = "CRV1:U2F,R:reg:%s:%s" % (b64user, b64reg)
            return reply
        except Exception as e:
            print "Failed buildU2FRegistration"
            print e
        return None

    def finishU2FRegistration(self, user, reply):
        try:
            response = self.u2fClient.register_complete(user, reply)
            #Not really required, will throw on error
            if "created" in response:
                return True
        except Exception as e:
            print "Failed finishU2FRegistration"
            print e
        return False

    def buildU2FAuth(self, user):
        try:
            data = self.u2fClient.auth_begin(user)
            #data = json.loads(str(data))
            response = {}
            #Start building
            response["challenge"] = data["challenge"]
            response["appId"] = data["appId"]
            #Grab the first keyHandle
            keyhandle = data["registeredKeys"][0]
            response["keyHandle"] = keyhandle["keyHandle"]
            response["version"] = keyhandle["version"]
            authstr = json.dumps(response)
            b64auth = b64encode(authstr)
            b64user = b64encode(user)
            reply = "CRV1:U2F:auth:%s:%s" % (b64user, b64auth)
            return reply
        except Exception as e:
            print "Failed buildU2FAuth"
            print e
        return None

    def finishU2FAuth(self, user, reply):
        try:
            response = self.u2fClient.auth_complete(user, reply)
            #Not really required, will throw on error
            if "created" in response:
                return True
        except Exception as e:
            print "Failed finishU2FAuth"
            print e
        return False

if __name__ == '__main__':
    authClient = OpenVPNU2FAuthPlugin("http://localhost:8080/openvpn")
    authClient.Run()