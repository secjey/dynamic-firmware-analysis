#!/usr/bin/env python

"""
This script enables users to automate firmware analysis tasks
such as the extraction or emulation process of firmware images
based on the Firmadyne system.
# https://github.com/firmadyne/firmadyne
"""

from __future__ import print_function
import sys, os, pexpect, argparse, re, signal, psutil, time

__author__ = "secjey"
__copyright__ = "Copyright 2017"
__credits__ = [""]
__license__ = "GPLv3"
__version__ = "1.0.1"
__maintainer__ = "secjey"
__status__ = "Development"

# CONFIGURATIONS - change this according to your system
FIRMADYNE_PATH = '/root/Desktop/firmware_analysis/tools/firmadyne'
OUTPUT_DIR = '{}/images'.format(FIRMADYNE_PATH)
DATABASE_NAME = 'firmware'
USER = 'firmadyne'
PASSWORD = 'firmadyne'
HOST = 'localhost'

sys.path.append(os.path.abspath(FIRMADYNE_PATH + "/scripts"))
sys.path.append(os.path.abspath(FIRMADYNE_PATH + "/sources/extractor"))
import extractor
import psycopg2

# COMMANDS
EXTRACTOR_COMMAND = '{0}/sources/extractor/extractor.py -b {1} -sql 127.0.0.1 -np -nk \"{2}\" {3}'
GETARCH_COMMAND = '{0}/scripts/getArch.sh {1}/{2}.tar.gz'
TAR2DB_COMMAND = '{0}/scripts/tar2db.py -i {1} -f {2}/{1}.tar.gz'
MAKEIMAGE_COMMAND = 'sudo {}/scripts/makeImage.sh {}'
INFERNETWORK_COMMAND = '{}/scripts/inferNetwork.sh {}'
EMULATE_COMMAND = '{}/scratch/{}/run.sh'
PURGE_COMMAND = '{}/scripts/delete.sh {}'

class bcolors:
	"""Defines some ANSI color codes."""
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	ITALIC = '\033[3m'
	UNDERLINE = '\033[4m'

def signal_handler(sig, frame):
    """Handles signals sent by the user.
    In the case the SIGINT signal is received, child processes will be stopped.
    """
    if sig == signal.SIGINT:
        print(bcolors.OKBLUE + "\n[-] The program is stopping..." + bcolors.ENDC)
        procs = psutil.Process().children(recursive=True)
        try:
		    for p in procs:
			    p.terminate()
		    gone, still_alive = psutil.wait_procs(psutil.Process().children(recursive=True), timeout=3)
		    for p in still_alive:
		        p.kill()
        except:
            pass
        sys.exit(0)

def welcome():
	"""Prints the welcome message at the start of the script."""
	print(bcolors.HEADER + """
	Welcome to the FIRMWARE AUTOMATION TOOL - v1.0.1
	This tool automates firmware analysis tasks
	such as the extraction or emulation process of firmware images
	based on the Firmadyne system.
	By secjey - https://github.com/secjey
	""" + bcolors.ENDC)

def parse_args():
	"""Parses the arguments passed in the command line."""
	parser = argparse.ArgumentParser(description='DESCRIPTION')
	parser.add_argument('firmware', help="Path to the firmware image")
	parser.add_argument('--purge', type=int, metavar="FIRMWARE_ID", help="Delete the whole project related to the provided id")	
	parser.add_argument('-b','--brand', dest='brand', help="Brand of the firmware image", default=None)
	parser.add_argument('-a','--arch', dest='arch', help="Architecture of the firmware image")

	# either skip or extract, both are not possible
	group = parser.add_mutually_exclusive_group()
	group.add_argument('--skip', type=int, dest='firmware_id', help="Skip the extraction process for the specified firmware id")
	group.add_argument('--extract-only', action="store_true", default=False, help="Perform the extraction only")
	return parser.parse_args()

def delete(id_del):
	"""Deletes information related to a specific project.

	id_del: ID of the project that will be deleted.
	"""
	print(bcolors.OKBLUE + "[-] Deleting the project..." + bcolors.ENDC)
	command = PURGE_COMMAND.format(FIRMADYNE_PATH, id_del)
	print(bcolors.ITALIC + command + bcolors.ENDC)
	delete = pexpect.spawn(command)
	# waiting for the command prompt
	# and then providing the password to connect to the db
	delete.expect('Password for user {}:'.format(USER))
	delete.sendline(PASSWORD)
	index = delete.expect('Done')
	print(bcolors.OKGREEN + "[+] Project successfully deleted!" + bcolors.ENDC)

def extract(firmware, brand, output_dir=OUTPUT_DIR, no_rootfs_extract=True, kernel_extract=False, parallel_op=False, sql_host=HOST):
	"""Extracts the firmware image thanks to the Extractor class of the Firmadyne system."""
	print(bcolors.OKBLUE + "[-] Extracting the firmware... Please be patient, it might take a while..." + bcolors.ENDC)
	command = EXTRACTOR_COMMAND.format(FIRMADYNE_PATH, brand, firmware, output_dir)
	print(bcolors.ITALIC + command + bcolors.ENDC)

	# Extractor(result.input, result.output, result.rootfs, result.kernel, result.parallel, result.sql, result.brand)
	# No extraction of the rootfs itself, no kernel extraction, no parallel operation
#	extract = extractor.Extractor(firmware, output_dir, no_rootfs_extract, kernel_extract, parallel_op, sql_host, brand)
#	extract.extract()

	extract = pexpect.spawn(command)
	index = extract.expect(['Connection refused', 'Database Image ID: .*\n'])
	if index == 0:
		print(bcolors.FAIL + "[!] Please ensure the postgresql service is running..." + bcolors.ENDC)
		sys.exit(0)
	elif index == 1:
		print(bcolors.OKGREEN + "[+] Your firmware image has been attributed the ID:" + extract.after.split('\n')[0].split(':')[1] + bcolors.ENDC)

	print(bcolors.OKBLUE + "[-] Still extracting the firmware..." + bcolors.ENDC)
	extract.interact()
	extract.expect(pexpect.EOF)
	database = psycopg2.connect(database=DATABASE_NAME,
	                            user=USER,
	                            password=PASSWORD,
	                            host=HOST)
	# querying the db to get the id that has been attributed to the firmware image
	# and to check whether the filesystem has been extracted (rootfs_extracted)
	with database.cursor() as cur:
		cur.execute("SELECT id, rootfs_extracted FROM image where filename = '{}'".format(os.path.basename(firmware)))
		firmware_id, status = cur.fetchone()
	cur.close()

	# this is required to not raise an error afterwards
	# as the current working directory is in /tmp and has been deleted
	# at the end of the extraction process
	os.chdir(FIRMADYNE_PATH)

	return (firmware_id, status)

def get_architecture(firmware_id):
	"""Gets the architecture of the given firmware image.""" 
	print(bcolors.OKBLUE + "[-] Getting the firmware architecture..." + bcolors.ENDC)
	command = GETARCH_COMMAND.format(FIRMADYNE_PATH, OUTPUT_DIR, firmware_id)
	print(bcolors.ITALIC + command + bcolors.ENDC)
	output = pexpect.run(command, events={'Password for user {}:'.format(USER):PASSWORD + '\n'})
	# extract the architecture info from the output
	arch = ""
	try:
		arch = output.split('\n')[0].split(':')[1]
	except:
		print(bcolors.FAIL + "[!] The firmware architecture couldn't be determined..." + bcolors.ENDC)
		print(bcolors.ITALIC + "[!] Please try manually with the file command and provide the correct architecture type with the --arch parameter..." + bcolors.ENDC)
	else:
		print(bcolors.OKGREEN + "[+] The architecture of your firmware image is:" + arch + bcolors.ENDC)
	return arch

def tar2db(firmware_id):
	"""Populates the db with information related to the filesystem."""
	print(bcolors.OKBLUE + "[-] Writing filesystem information into database..." + bcolors.ENDC)
	command = TAR2DB_COMMAND.format(FIRMADYNE_PATH, firmware_id, OUTPUT_DIR)
	print(bcolors.ITALIC + command + bcolors.ENDC)
	tar2db = pexpect.spawn(command)
	# either an error is raised because keys already exist
	# which means the info has already been written in the db
	# or the command terminates properly
	index = tar2db.expect(['Key.*already exists', 'No such file or directory: .*\n', pexpect.EOF])
	if index == 0:
		print(bcolors.WARNING + "[!] This step was already performed earlier..." + bcolors.ENDC)
		return True
	elif index == 1:
		missing_file = tar2db.after.split('\n')[0].split(':')[1].strip()
		print(bcolors.FAIL + "[!] The file {} does not exist...".format(missing_file) + bcolors.ENDC)
		return False
	else:
		print(bcolors.OKGREEN + "[+] Filesystem information successfully written!" + bcolors.ENDC)
	return True

def make_image(firmware_id, arch):
	"""Creates the QEMU disk image for the firmware."""
	print(bcolors.OKBLUE + "[-] Creating the QEMU disk image for the firmware..." + bcolors.ENDC)
	command = MAKEIMAGE_COMMAND.format(FIRMADYNE_PATH, firmware_id) + " " + arch
	print(bcolors.ITALIC + command + bcolors.ENDC)
	make_image = pexpect.spawn(command)
	# if proceed anyway appears, it means the filesystem was already mounted
	index =	make_image.expect(['Proceed anyway?', pexpect.EOF])
	if index == 0:
		info = re.search('last mounted on (.*)', make_image.before).group(1)
		print(bcolors.WARNING + "[!] /dev/mapper/loop0p1 already contains a filesystem which was mounted on " + info + bcolors.ENDC)
		make_image.sendline('y') # in case /dev/mapper/loop0p1 already contains a file system, say 'yes' to proceed anyway
	print(bcolors.OKGREEN + "[+] QEMU disk image successfully created!" + bcolors.ENDC)

def network_setup(firmware_id, arch):
	"""Determines the network configuration of the firmware by emulating it for a certain amount of time."""
	runtime = 60
	print(bcolors.OKBLUE + "[-] Determining the network configuration of the firmware..." + bcolors.ENDC)
	print(bcolors.OKBLUE + "[-] The firmware will now be running for {} seconds...".format(runtime) + bcolors.ENDC)
	command = INFERNETWORK_COMMAND.format(FIRMADYNE_PATH, firmware_id) + " " + arch
	print(bcolors.ITALIC + command + bcolors.ENDC)
	setup = pexpect.spawn(command, timeout=runtime + 5)
	# info should be provided as regards the interfaces available to access the emulated firmware
	setup.expect('Interfaces: \[(.*)\]\n')

	if setup.match.group(1) == "":
		print(bcolors.WARNING + "[!] No network interface could be determined..." + bcolors.ENDC)
		return False
	else:
		print(bcolors.OKGREEN + "[+] Your firmware will be accessible at {}!".format(setup.match.group(1)) + bcolors.ENDC)
		return True

def emulate(firmware_id):
	"""Emulates the firmware with the inferred network configuration."""
	print(bcolors.OKBLUE + "[-] Emulating the firmware with the inferred network configuration..." + bcolors.ENDC)
	print(bcolors.OKBLUE + "[-] Use CTRL-A + X to exit QEMU..." + bcolors.ENDC)
	command = EMULATE_COMMAND.format(FIRMADYNE_PATH, firmware_id)
	print(bcolors.ITALIC + command + bcolors.ENDC)
	emulation = pexpect.spawn(command)
	# wait so that the user has enough time to read the info at the start
	time.sleep(5)
	# let the user take control of the QEMU emulation
	emulation.interact()

def main():
	welcome()
	result = parse_args()
	signal.signal(signal.SIGINT, signal_handler) # catch ctrl+c

	if result.purge:
		delete(result.purge)
		return
	
	firmware_id = result.firmware_id
	if not result.firmware_id:

		firmware_id, extracted = extract(result.firmware, result.brand)
		if not extracted:
			print(bcolors.FAIL + "[!] The firmware extraction failed..." + bcolors.ENDC)
			print(bcolors.ITALIC + "[!] Please try manually with the Firmware Modification Kit and compress the filesystem into a .tar.gz archive placed in the {} directory.".format(OUTPUT_DIR) + bcolors.ENDC)
			print(bcolors.ITALIC + "[!] You can then skip the extraction process with the --skip parameter and your firmware id '{}'.".format(firmware_id) + bcolors.ENDC)
			return
		print(bcolors.OKGREEN + "[+] Firmware successfully extracted!" + bcolors.ENDC)

	if not result.extract_only:

		arch = result.arch if result.arch else get_architecture(firmware_id)

		if arch != "":
			if tar2db(firmware_id) != False:
				make_image(firmware_id, arch)
				if network_setup(firmware_id, arch) == False:
						print(bcolors.WARNING + "[!] The firmware will still be emulated but you will have to manually configure QEMU\nin the QEMU monitor console to access your emulated firmware from your host..." + bcolors.ENDC)
				emulate(firmware_id)

if __name__ == '__main__':
	main()
