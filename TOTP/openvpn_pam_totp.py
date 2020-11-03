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

# PyOTP - https://github.com/pyauth/pyotp

# This script has been written to accompany:
# https://sparklabs.com/support/kb/article/totp-two-factor-authentication-with-openvpn-and-viscosity/


import sys, os, logging, pickle
import pam, pyotp
from base64 import b64decode

class OpenVPNPYOTPAuth:
	def __init__(self, dbPath):
		logging.basicConfig()
		self.dbPath = dbPath

	def AuthUser(self, username, password):
		# Extract the token from the encoded password
		if password.startswith('SCRV1:'):
			# Extract the actual password and token
			passwordSplit = password.split(':')
			password = b64decode(passwordSplit[1])
			otp = int(b64decode(passwordSplit[2]))
		else:
			# Invalid data
			return False

		# Check username and password are valid using PAM
		try:
			p = pam.pam()
			loginValid = pam.authenticate(username, password)
		except:
			loginValid = False

		if not loginValid:
			return False

		# Get the users base32 ID from the database
		if os.path.exists(self.dbPath):
			try:
				file = open(self.dbPath,'rb')
				tokenDb = pickle.load(file)
				file.close()
			except:
				tokenDb = {}
		else:
			tokenDb = {}

		if not username in tokenDb.keys():
			# User not setup for OTP
			return False
			
		#Check the OTP, allowing a 1 tick leeway (i.e. the previous and next code will work)
		try:
			return pyotp.totp.TOTP(tokenDb[username]).verify(otp, valid_window=1)
		except:
			return False
			
		return False

if __name__ == "__main__":
	# Read in the username and password from the environment
	dbPath = '/etc/openvpn/pyotp_index.db'
	serverName = "OpenVPN Server"
	
	if len(sys.argv) == 3 and sys.argv[1] == "--genkey":
		username = str(sys.argv[2])
		# Get the pickle database
		if os.path.exists(dbPath):
			try:
				file = open(dbPath,'rb')
				tokenDb = pickle.load(file)
				file.close()
			except:
				tokenDb = {}
		else:
			tokenDb = {}
		
		# Gen key for user, store, then display
		b32 = pyotp.random_base32()
		totp = pyotp.totp.TOTP(b32)
		
		tokenDb[username] = b32
		
		file = open(dbPath,'wb')
		pickle.dump(tokenDb, file, -1)
		file.close()
		
		print(username)
		print(b32)
		print(totp.provisioning_uri(username, issuer_name=serverName))
		exit(0)
		
	# Run for OpenVPN
	username = os.environ['username']
	password = os.environ['password']
	authClient = OpenVPNPYOTPAuth(dbPath)
	if authClient.AuthUser(username, password):
		sys.exit(0)
	sys.exit(1)
