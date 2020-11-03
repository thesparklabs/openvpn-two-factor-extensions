#!/usr/bin/python3
# Copyright (C) 2018 SparkLabs Pty Ltd
#
# This file is part of OpenVPN OTP Server Support.
#
# OpenVPN OTP Server Support is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# OpenVPN OTP Server Support is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenVPN OTP Server Support.  If not, see <http://www.gnu.org/licenses/>.

# Duo Security - https://duo.com/

# This script has been written to accompany:
# https://sparklabs.com/support/kb/article/totp-two-factor-authentication-with-openvpn-and-viscosity/


import sys, os, logging, pickle
import pam, duo_client, duo_client.auth_v1
from base64 import b64decode

class OpenVPNDuoAuth:
	def __init__(self, ikey, skey, host):
		logging.basicConfig()
		self.ikey = ikey
		self.skey = skey
		self.host = host

	def AuthUser(self, username, password, ipAddr):
		# Extract the token from the encoded password
		if password.startswith('SCRV1:'):
			# Extract the actual password and token
			passwordSplit = password.split(':')
			password = b64decode(passwordSplit[1])
			challenge = b64decode(passwordSplit[2])
			# Python3 gotcha, convert from byte object to string
			token = "".join(chr(c) for c in challenge)
		else:
			# Invalid data
			return False

		# Check username and password are valid using PAM
		try:
			p = pam.pam()
			loginValid = p.authenticate(username, password)
		except:
			loginValid = False

		if not loginValid:
			return False

		duoAuth = duo_client.auth_v1.AuthV1(self.ikey, self.skey, self.host)
		#Preauth the user in duo, using the V1 API
		response = duoAuth.preauth(username, ipAddr)
		if not response['result'] in ('allow', 'auth'):
			# User is not permitted or not enrolled
			return False
			
		# User allowed to bypass 2FA? If so, allow
		if response['result'] == 'allow':
			return True
			
		# Auth the user using the v1 API auto feature
		# NOTE - If using SMS or Phone, the user will be given an auth failure, and will automatically
		# reconnect to enter code from SMS or phone call
		return duoAuth.auth(username, factor='auto', auto=token, ipaddr=ipAddr)

if __name__ == "__main__":
	#------------------------------------------------------------------------------
	# VARIABLES
	#------------------------------------------------------------------------------
	duo_ikey = 'YOUR_INTEGRATION_KEY'
	duo_skey = 'YOUR_SECRET_KEY'
	duo_host = 'api-XXXXXXXX.duosecurity.com'
	#------------------------------------------------------------------------------
	
	# Read in the username and password from the environment
	username = os.environ['username']
	password = os.environ['password']
	ipAddr = os.environ['untrusted_ip']
	authClient = OpenVPNDuoAuth(duo_ikey, duo_skey, duo_host)
	if authClient.AuthUser(username, password, ipAddr):
		sys.exit(0)
	sys.exit(1)
