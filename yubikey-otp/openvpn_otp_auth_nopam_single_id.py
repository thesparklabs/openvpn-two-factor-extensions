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
from yubico_client import Yubico

class OpenVPNOTPAuth:
	def __init__(self, keyId, clientID, secretKey):
                self.clientID = clientID
		self.secretKey = secretKey
                self.keyId = keyId
	def AuthUser(self, token):
		# The first 12 characters of the token is the unique public ID
                tokenId = token[:12]
                if tokenId != self.keyId:
                        return False

		# Check that the token is valid using the Yubico Cloud service
		yubico = Yubico(self.clientID, self.secretKey)
		try:
			tokenValid = yubico.verify(token)
		except:
			tokenValid = False

		if not tokenValid:
			return False

		return True

if __name__ == "__main__":
	logging.basicConfig()
        password = os.environ['password']
	yubicoClientId = 'CLIENT_ID'
	yubicoSecretKey = 'SECRET_KEY'
        keyId = 'YOUR_KEY_ID_FIRST_12_CHARACTERS_OF_YUBIKEY_OUTPUT'

        logging.debug('token '+password)
	
        authClient = OpenVPNOTPAuth(keyId, yubicoClientId, yubicoSecretKey)
	if authClient.AuthUser(password):
		sys.exit(0)
	sys.exit(1)
