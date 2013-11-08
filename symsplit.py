#! /usr/bin/python
"""
Symmetric secret sharing.
"""

import hashlib, struct, os, subprocess

def choose(n, k, start=0):
	if k:
		for i in xrange(start, n):
			for remaining in choose(n, k-1, i+1):
				yield [i] + remaining
	else: yield []

def hashalg(s):
	for i in xrange(2):
		s = hashlib.sha512(s).digest()
	return s

def verify_share(s):
	return hashalg(s[:-1])[0] == s[-1]

def ser(l):
	return "".join(i.encode("hex")+":" for i in l)

def deser(s):
	return [i.decode("hex") for i in s.split(":")[:-1]]

def symmetric(block, key, operation):
	in_fd, out_fd = os.pipe()
	os.write(out_fd, key.encode("hex"))
	os.close(out_fd)
	operation = {"enc": "--symmetric", "dec": "--decrypt"}[operation]
	proc = subprocess.Popen(["gpg", "-q", operation, "--cipher-algo", "AES", "--passphrase-fd", str(in_fd), "-"],
		stdin=subprocess.PIPE,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE)
	stdout, stderr = proc.communicate(block)
	return stdout

def split_secret(secret, n, k):
	"""split_secret(secret, n, k) -> shares, common

	Splits s into n shares, such that join_shares(shares[:k], common) == secret.
	"""
	# Start by padding the secret, to hide its length.
	#secret = struct.pack("<I", len(secret)) + secret
	#secret += "\0"*(256-len(secret))
	# Generate some random shares.
	shares = [chr(i) + os.urandom(20) for i in xrange(n)]
	# Add a one byte checksum.
	for i in xrange(n):
		shares[i] += hashalg(shares[i])[0]
	common = [chr(n), chr(k)]

	for ind in choose(n, k):
		subset = map(shares.__getitem__, ind)
		subset.sort()
		key = hashalg("".join(subset))
		common.append(symmetric(secret, key, "enc"))

	common = ser(common)
	return shares, common

def join_shares(shares, common):
	# Verify the shares.
	assert all(map(verify_share, shares)), "Invalid checksum on share."
	shares.sort()
	key = hashalg("".join(shares))
	# Extract the appropriate encrypted block.
	n, k = map(ord, common[:2])
	assert len(shares) >= k, "Too few shares."
	shares = shares[:k] # Accept being given too many shares.
	indexes = [ord(share[0]) for share in shares]
	block_index = list(choose(n, k)).index(indexes)
	block = common[block_index+2]
	return symmetric(block, key, "dec")

if __name__ == "__main__":
	import sys, getpass
	if len(sys.argv) == 3:
		n, k = map(int, sys.argv[2:])
		#secret = getpass.getpass("Paste in secret data: ")
		secret = open(sys.argv[1]).read()
		shares, common = split_secnret(secret, n, k)
		for i, share in enumerate(shares):
			fd = open("share%i" % i, "w")
			fd.write(share.encode("hex") + "\n")
			fd.close()
		fd = open("common", "w")
		fd.write(common+"\n")
		fd.close()
	elif len(sys.argv) == 2:
		common = deser(open(sys.argv[1]).read())
		shares = []
		n, k = map(ord, common[:2])
		for i in xrange(k):
			share = getpass.getpass("Share %i/%i: " % (i+1, k)).strip().decode("hex")
			assert verify_share(share), "Invalid share."
			shares.append(share)
		block = join_shares(shares, common)
		fd = open(sys.argv[2], "w")
		fd.write(block)
		fd.close()
	else:
		print "usage: symsplit n k | symsplit common"
		print "If 2 arguments:"
		print "  Writes out files share0, share1, ... share{n-1}, and common."
		print "If 1 argument:"
		print "  Writes the results to stdout."
		exit(2)

