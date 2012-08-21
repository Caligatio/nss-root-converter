#!/usr/bin/env python3
'''
Copyright (c) 2012, Brian Turek
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
 * The names of the contributors may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
ANDANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIEDWARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT,INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING,BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE,DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OFLIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCEOR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISEDOF THE POSSIBILITY OF SUCH DAMAGE.
'''

from gzip import GzipFile
from io import BytesIO
from base64 import b64encode
from textwrap import wrap
from urllib.request import urlopen, Request
from argparse import ArgumentParser
import sys
import ssl
import re

def fetchUrl(url, caFile = None, caPath = None):
	'''
	fetchUrl(url[, caFile = None]) -> bytes

	Gets the contents of a URL, performing GZip decoding if needed
	'''
	# Setup headers to be used with accessing Southwest's website
	headers = {'Accept-Encoding': 'gzip'}

	request = Request(url, None, headers)
	sock = urlopen(request, cafile = caFile, capath = caPath)
	data = sock.read()

	# Check for GZip encoding and decode if needed
	if (sock.headers.get('content-encoding', None) == 'gzip'):
		data = GzipFile(fileobj=BytesIO(data)).read()

	return data

def parseNSSFile(caFile = None, caPath = None, explicitTrustOnly = True,
	trustServerAuth = True, trustEmailProtection = False,
	trustCodeSigning = False):
	'''
	parseNSSFile([caFile = None, caPath = None, explicitTrustOnly = True,
		trustServerAuth = True, trustEmailProtection = False,
		trustCodeSigning = False]) -> tuple

	Downloads and parses out the license, date, and trusted certificate roots
	contained in the NSS certificate root file.
	'''
	objs = []
	currObj = None
	license = None
	date = None

	if ((None == caFile) and (None == caPath)):
		sys.stdout.write("Warning: accessing the NSS certificate root file without SSL validation\n")

	try:
		raw = fetchUrl('https://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1',
			caFile, caPath)
	except (ssl.SSLError) as e:
		sys.stderr.write("Error: cannot find needed SSL certificate in CAFile, aborting\n")
		return None

	content = raw.decode('utf-8')

	lines = content.splitlines()

	for (i, line) in enumerate(lines):
		if (-1 != line.find('This Source Code Form')):
			license = getLicense(lines, i)

		if (line.startswith('CVS_ID')):
			date = re.findall('\$Date: (.*) \$', line)[0]

		if (not line.startswith('CKA')):
			continue

		words = line.split(' ', 2)

		if ("CKA_CLASS" == words[0]):
			if (None != currObj):
				objs.append(currObj)

			currObj = {}

		if ('MULTILINE_OCTAL' == words[1]):
			value = parseMultlineOctal(lines, i + 1)
		else:
			value = words[2]

		currObj[words[0]] = {'type' : words[1], 'value' : value}

	certs = (x for x in objs if x['CKA_CLASS']['value'] == 'CKO_CERTIFICATE')
	trusts = [x for x in objs if x['CKA_CLASS']['value'] == 'CKO_NSS_TRUST']

	trustedCerts = []
	for cert in certs:
		if	(isCertTrusted(cert, trusts, explicitTrustOnly, trustServerAuth,
				trustEmailProtection, trustCodeSigning)):
			trustedCerts.append(cert)

	return (license, date, trustedCerts)

def parseMultlineOctal(lines, num):
	'''
	parseMultlineOctal(lines, num) -> list(number)

	Parses out a MULTILINE_OCTAL block and returns a list of the byte contents
	'''
	value = []

	while True:
		if ('END' == lines[num]):
			# Convert octal digits into ints using map/lambda
			return bytes(map(lambda x: int(x, 8), value))
		elif (lines[num].startswith('\\')):
			# Skip the first item as its empty
			value.extend(lines[num].split('\\')[1:])
		else:
			return None
		num += 1

def getLicense(lines, num):
	'''
	getLicense(lines, num) -> string

	Parses out the license and returns it as a single string
	'''
	license = []

	while True:
		if (lines[num].startswith('CVS_ID')):
			break
		license.append(lines[num][2:])

		num += 1

	return ' '.join(license)

def isCertTrusted(cert, trusts, explicitTrustOnly, trustServerAuth,
		trustEmailProtection, trustCodeSigning):
	'''
	isCertTrusted(cert, trusts, explicitTrustOnly, trustServerAuth,
		trustEmailProtection, trustCodeSigning) -> boolean

	Examines a certificate and evaluates it against the trust objects and
	criteria to determine if it should be trusted
	'''
	issuer = cert['CKA_ISSUER']['value']
	serial = cert['CKA_SERIAL_NUMBER']['value']

	for trust in trusts:
		if ((trust['CKA_ISSUER']['value'] == issuer) and (trust['CKA_SERIAL_NUMBER']['value'] == serial)):
			if (trustServerAuth):
				if (	(trust['CKA_TRUST_SERVER_AUTH']['value'] == 'CKT_NSS_TRUSTED_DELEGATOR')
						or (	(trust['CKA_TRUST_SERVER_AUTH']['value'] == 'CKT_NSS_MUST_VERIFY_TRUST')
							and (not explicitTrustOnly)
						)
					):
						return True

			if (trustEmailProtection):
				if (	(trust['CKA_TRUST_EMAIL_PROTECTION']['value'] == 'CKT_NSS_TRUSTED_DELEGATOR')
						or (	(trust['CKA_TRUST_EMAIL_PROTECTION']['value'] == 'CKT_NSS_MUST_VERIFY_TRUST')
							and (not explicitTrustOnly)
						)
					):
						return True

			if (trustCodeSigning):
				if (	(trust['CKA_TRUST_CODE_SIGNING']['value'] == 'CKT_NSS_TRUSTED_DELEGATOR')
					or (	(trust['CKA_TRUST_CODE_SIGNING']['value'] == 'CKT_NSS_MUST_VERIFY_TRUST')
						and (not explicitTrustOnly)
					)
				):
					return True

	else:
		return False

def main(outFile, caFile = None, caPath = None, explicitTrustOnly = True,
	trustServerAuth = True, trustEmailProtection = False,
	trustCodeSigning = False):
	'''
	main(outFile, caFile = None, caPath = None, explicitTrustOnly = True,
		trustServerAuth = True, trustEmailProtection = False,
		trustCodeSigning = False)

	Downloads and parses the NSS certificate root file, writing out the license,
	data, and trusted certificates to a PEM file
	'''
	parsedNSS = parseNSSFile(caFile,
					caPath,
					explicitTrustOnly,
					trustServerAuth,
					trustEmailProtection,
					trustCodeSigning)

	if (None == parsedNSS):
		sys.stderr.write("Could not find any certificates\n")
		return

	try:
		f = open(outFile, 'wt', encoding='utf-8')
	except (IOError) as e:
		sys.stderr.write("Error: could not open output file\n")
		return

	f.write("\n".join(
		wrap(
			parsedNSS[0],
			76,
			initial_indent = '## ',
			subsequent_indent = '## '
		)
	) + "\n")

	f.write("\n## Date: " + parsedNSS[1] + "\n\n")

	for trustedCert in parsedNSS[2]:
		name = trustedCert['CKA_LABEL']['value'].strip("\"")

		f.write(name + "\n")
		f.write("=" * len(name) + "\n")
		f.write("-----BEGIN CERTIFICATE-----\n")
		f.write("\n".join(
			wrapB64(
				b64encode(trustedCert['CKA_VALUE']['value']).decode('utf-8'),
				76)
			) + "\n")
		f.write("-----END CERTIFICATE-----\n\n")

	f.close()

def wrapB64(str, width = 70):
	'''
	wrapB64(str[, width = 70]) -> list(str)

	Wraps a string that was base-64 encoded to a set width.  textwrap.wrap
	is extremely slow at contiguous strings
	'''
	offset = 0
	retVal = []
	strLen = len(str)

	while True:
		line = str[offset : offset + width]
		retVal.append(line)

		if ((offset + width) >= strLen):
			break

		offset += width

	return retVal

if (__name__ == "__main__"):
	parser = ArgumentParser(
		description = 'Downloads the Mozilla NSS root certificates and coverts to PEM format')
	parser.add_argument('outFile', help = 'Output filename for PEM certificates')
	parser.add_argument('--caFile', dest = 'caFile', metavar = 'FILE',
		default = None,
		help = 'CAChain file to be used to obtain the NSS root certificates')
	parser.add_argument('--caPath', dest = 'caPath', metavar = 'DIR',
		default = None,
		help = 'Path to directory of PEM formatted certificates to be used to obtain the NSS root certificates')
	parser.add_argument('--trustExplictOnly', action = 'store_true',
		default = True)
	parser.add_argument('--trustServerAuth', action = 'store_true',
		default = True)
	parser.add_argument('--trustEmailProtection', action = 'store_true',
		default = False)
	parser.add_argument('--trustCodeSigning', action = 'store_true',
		default = False)

	args = parser.parse_args()

	main(args.outFile, args.caFile, args.caPath, args.trustExplictOnly, args.trustServerAuth,
		args.trustEmailProtection, args.trustCodeSigning)
