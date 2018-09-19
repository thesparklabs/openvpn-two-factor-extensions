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

# This script has been written to accompany:
# https://www.sparklabs.com/support/kb/article/yubikey-u2f-two-factor-authentication-with-openvpn-and-viscosity/

import sys, os
import telnetlib
import pam, json, zlib
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

class OpenVPNU2FAuth:
    def __init__(self, openVpnPort, u2fvalAddress):
        self.port = openVpnPort
        self.conn = telnetlib.Telnet()
        self.u2fClient = Client(u2fvalAddress)

        self.clientID = None
        self.clientKID = None
        self.clientData = {}

    def close():
        try:
            self.conn.close()
        except:
            pass
    
    def Connect(self):
        try:
            self.conn.open('127.0.0.1', self.port)
            print "Connected"

            while True:
                try:
                    line = self.conn.read_until("\n")
                except:
                    break

                line = line.replace("\n", "").replace("\r", "").strip()
                if line == "":
                    pass
                
                self.processCommand(line)            

        except Exception as e:
            print "Connection to OpenVPN failed."
            print e

    def processCommand(self, line):
        split = line.split(':', 1)
        if len(split) != 2:
            return #Ignore
        command = split[0]
        content = split[1]

        if command == ">CLIENT":
            parts = content.split(',', 1)
            if len(parts) != 2:
                return
            if parts[0] == "CONNECT":
                self.clientData = {}
                cids = parts[1].split(',')
                self.clientID = cids[0]
                if len(cids) > 1:
                    self.clientKID = cids[1]
                else:
                    self.clientKID = None

            elif parts[0] == "ENV":
                #Make sure we got a CONNECT
                if self.clientID == None:
                    return
                if parts[1] == "END":
                    #Send the client data
                    self.authUser(self.clientID, self.clientKID, self.clientData)
                    #Clear
                    self.clientID = None
                    self.clientKID = None
                    self.clientData = {}
                    return

                env = parts[1].split('=', 1)
                if len(env) != 2:
                    return
                self.clientData[env[0]] = env[1]

    def authUser(self, cid, kid, cdata):
        if kid == None:
            return
        if not 'username' in cdata or not 'password' in cdata:
            self.clientDeny(cid, kid, "Client Data missing")
        
        username = cdata['username']
        password = cdata['password']
        
        try:
            if password.startswith('CRV1:'):
                # Extract the actual password and token
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
                    print "Finish U2F Registration for %s" % username
                    #Adds required version field...
                    response["version"] = "U2F_V2"
                    success = self.finishU2FRegistration(username, json.dumps(response))
                    if success:
                        #Now Auth
                        reply = self.buildU2FAuth(username)
                        self.clientDeny(cid, kid, "U2F Reg Required", reply)
                else:
                    print "Finish U2F Auth for %s" % username
                    success = self.finishU2FAuth(username, json.dumps(response))
                    if success:
                        print "User %s Authenticated" % username
                        #Let the user connect
                        self.clientAllow(cid, kid)


                return #Past here is a standard auth attempt

            #PAM authenticate
            try:
                loginValid = pam.authenticate(username, password)
            except:
                loginValid = False

            if not loginValid:
                self.clientDeny(cid, kid, "PAM Auth failed")
                return

            #Check if the user has a device already registered
            if self.userNeedsRegistration(username):
                #Send a registration request
                print "U2F Registration required for %s" % username
                reply = self.buildU2FRegistration(username)
                self.clientDeny(cid, kid, "U2F Reg Required", reply)
            else:
                #Send an auth request
                print "U2F Authentication required for %s" % username
                reply = self.buildU2FAuth(username)
                self.clientDeny(cid, kid, "U2F Reg Required", reply)
        except Exception as e:
            print "Failed to authUser"
            print e
            #Reject the user
            self.clientDeny(cid, kid, "Failed authUser")

    def clientDeny(self, cid, kid, reason, clientReason=None):
        reply = "client-deny %s %s \"%s\"" % (cid, kid, reason)
        if clientReason != None:
            reply += " \"%s\"" % clientReason
        reply += "\n"
        self.conn.write(reply)

    def clientAllow(self, cid, kid):
        reply = "client-auth-nt %s %s\n" % (cid, kid)
        self.conn.write(reply)

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
        return "U2F Registration Failed"

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
        return "U2F Auth Failed"

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

if __name__ == "__main__":
    # Find port number defined
    if not "--port" in sys.argv:
        print "Missing --port command"
        exit(1)
    portCommand = sys.argv.index("--port")
    if len(sys.argv) - 2 < portCommand:
        print "Need port number following --port"
        exit(1)
    port = int(sys.argv[portCommand + 1])

    #Connect to OpenVPN
    authClient = OpenVPNU2FAuth(port, 'http://localhost:8080/openvpn')
    authClient.Connect()
