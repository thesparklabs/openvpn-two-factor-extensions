#!/usr/bin/python
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

# This script has been written to accompany:
# https://www.sparklabs.com/support/kb/article/yubikey-otp-two-factor-authentication-with-openvpn-and-viscosity/


import sys, os, logging
import pam
from base64 import b64decode
import cPickle as pickle
from yubico_client import Yubico

class OpenVPNOTPAuth:
	def __init__(self, dbPath, clientID, secretKey):
		logging.basicConfig()
		self.dbPath = dbPath
		self.clientID = clientID
		self.secretKey = secretKey

	def AuthUser(self, username, password):
		# Extract the token from the encoded password
		if password.startswith('SCRV1:'):
			# Extract the actual password and token
			passwordSplit = password.split(':')
			password = b64decode(passwordSplit[1])
			token = b64decode(passwordSplit[2])
		else:
			# Invalid data
			return False

		# Check username and password are valid using PAM
		try:
			loginValid = pam.authenticate(username, password)
		except:
			loginValid = False

		if not loginValid:
			return False

		# The first 12 characters of the token is the unique public ID
		tokenId = token[:12]

		# Only accept the token assigned to the user. If this is the first time
		# a token has been used for a user, assign it to the user.		
		if os.path.exists(self.dbPath):
			try:
				file = open(self.dbPath,'rb')
				tokenDb = pickle.load(file)
				file.close()
			except:
				tokenDb = {}
		else:
			tokenDb = {}

		updateDb = False
		if username in tokenDb.keys() and tokenDb[username] != tokenId:
			# The token being used does not match the token for the user
			return False
		else:
			tokenDb[username] = tokenId
			updateDb = True
			
		# Check that the token is valid using the Yubico Cloud service
		yubico = Yubico(self.clientID, self.secretKey)

		try:
			tokenValid = yubico.verify(token)
		except:
			tokenValid = False

		if not tokenValid:
			return False

		# Save the token database if necessary
		if updateDb:
			file = open(self.dbPath,'wb')
			pickle.dump(tokenDb, file, -1)
			file.close()
		
		return True


if __name__ == "__main__":
	# Read in the username and password from the environment
	username = os.environ['username']
	password = os.environ['password']
	dbPath = '/etc/openvpn/token_index.db'
	yubicoClientId = 'YOURCLIENTID'
	yubicoSecretKey = 'YOURSECRETKEY'

	authClient = OpenVPNOTPAuth(dbPath, yubicoClientId, yubicoSecretKey)
	if authClient.AuthUser(username, password):
		sys.exit(0)
	sys.exit(1)
