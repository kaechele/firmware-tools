#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  getkey-bococom.py
#  Get keys for Bococom-type obfuscated firmware image files
#  
#  Copyright 2013 Felix Kaechele <felix@fetzig.org>
#  Copyright 2013 Michel Stempin <michel.stempin@wanadoo.fr>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  
from optparse import OptionParser

# String: "Linux Kernel Image"
knownstring = ['\x4c', '\x69', '\x6e', '\x75', '\x78', '\x20', '\x4b', '\x65', '\x72', '\x6e', '\x65', '\x6c', '\x20', '\x49', '\x6d', '\x61', '\x67', '\x65']
uimage_header = ['\x27', '\x05', '\x19', '\x56']

def read_firmware(inputfile):
	f = open(inputfile, 'r')
	
	# Get image magic
	pos = f.seek(0, 0)
	fstr = f.read(4)
	magic = fstr[3] + fstr[2] + fstr[1] + fstr[0]
	
	# Get encoded uImage header
	pos = f.seek(28, 0)
	fstr = f.read(4)
	enc_uimage = fstr
	
	# Get encoded known string (usually located at offset 60 (0x3C))
	pos = f.seek(60, 0)
	fstr = f.read(18)
	enc_key = fstr
	
	return magic, enc_uimage, enc_key

def get_key(knownstring, enc_key):
	ret = list(knownstring)
	for i, v in enumerate(knownstring):
		ret[i] = chr(ord(enc_key[i]) ^ ord(knownstring[i]))
	return ret[13:15] + ret[0:13]

def check_uimage_header(enc_uimage, key):
	test = list(uimage_header)
	for i, v in enumerate(enc_uimage):
		test[i] = chr(ord(enc_uimage[i]) ^ ord(key[i]))
	return test == uimage_header

def to_hex(string):
	return "".join([hex(ord(c))[2:].zfill(2) for c in string])

def to_c_list(string):
	ckey = "{"
	for char in string:
		byte = hex(ord(char))
		ckey += byte[0:2] + byte[2:4].upper() + ", "
	ckey = ckey[:-2] + "}"
	return ckey

def main():
	parser = OptionParser()
	parser.add_option("-i", "--input", action="store", dest="inputfile", help="path to input file", metavar="FILE")
	(options, args) = parser.parse_args()

	if options.inputfile == None:
		parser.error("Path to input file needed")
	
	(magic, enc_uimage, enc_key) = read_firmware(options.inputfile)
	key = get_key(knownstring, enc_key)
	print "Magic:\t\t0x" + to_hex(magic) + " (ASCII: " + magic + ")"
	print "Key:\t\t" + to_c_list(key)
	print "Validity:\t",
	if check_uimage_header(enc_uimage, key):
		print "Header looks like uImage. Key valid!"
	else:
		print "Header doesn't look like uImage. Key invalid!"
	
	return 0

if __name__ == '__main__':
	main()

