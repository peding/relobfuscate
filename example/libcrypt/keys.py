import os

plain1 = "hello from key1.so                \x00"
plain2 = "this message is brought by key2.so\x00"

dir = os.path.dirname(os.path.realpath(__file__)) + "/"


def write_asm(path, msg):
	if msg == "":
		return

	syms = sorted(zip(map(ord, msg), range(len(msg))))
	offset = 0
	skip = 0

	print(syms)

	with open(path, "w") as f:
		f.write(".data\n")
		f.write(".global asdf\n")
		f.write("asdf: .quad 0\n")

		for i in range(len(msg)):
			f.write(".global s%d\n" % i)

		f.write(".align 0x100\n")

		for (i, s) in syms:
			if i - offset > 0:
				skip = i - offset
				f.write(".skip %d\n" % skip)

			f.write("s%d: " % s)
			offset = i

		f.write("\n")


write_asm(dir + "key1.s", plain1)
write_asm(dir + "key2.s", plain2)

with open(dir + "libcrypt.rlc", "w") as f:

	for i in range(max(len(plain1), len(plain2))):
		f.write("ADDR8 s%d 0 -overwrite -dirty\n" % i)
		f.write("s+%d: | 00 |\n" % i)
