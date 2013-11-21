# Metascan Online Email Relay
# Author: Matthew Ghafary
# Date Published: Nov. 18, 2013
# OPSwat Student Programming Competition Fall 2013
import Queue
import StringIO
import urllib2 # For POST
import time
import json
from email import *
import smtplib # SMTP Client
import smtpd # SMTP Server
import asyncore
from io import BytesIO
from email.mime.base import MIMEBase
from email.encoders import encode_base64

# Constants that are configurable for System administrators.
# Explained in README
LISTEN_ON = 'YOUR DOMAIN OR IP'
LISTEN_ON_PORT = 25
MAIL_SERVER_DEST = 'THE SERVER TO DELIVER TO'
MAIL_SERVER_PORT = '587'
META_SCAN_API_LINK = 'https://api.metascan-online.com/v1/file' # Probably shouldn't change.
META_SCAN_API_KEY = 'READ INSRUCTIONS ON OBTAINING API KEY'
SCAN_LOOKUP_SLEEP_TIME = 5 # Seconds
SCAN_MAX_LOOKUP_TIME = 30 # Seconds

class CustomSMTPServer(smtpd.SMTPServer):
    
    def process_message(self, peer, mailfrom, rcpttos, data):
		
		email = message_from_string(data) # Convert Data string into python email.
		
		orig_subject = email['subject'] # Will use this when we need to modify subject.
		
		# Scan email for attachments. Return Queue of attachments.
		filesToScan = find_attachments(email)
	
		if filesToScan.empty(): # If there are no attachments, just send the email.
			send_message(email)
			return
	
		# At least one attachment found.
		# Pass the queue of files in, and return the file_id's.
		file_id = scan_attachments(filesToScan)
	
		if not file_id: # Metascan problem, no file_ids.
			del email['subject'] # NEED to delete subject from email, or possible errors.
			email['subject'] = '[File_ID_ERROR] - ' + orig_subject
			send_message(email)
			return 
	
		# File_IDs were received successfully.
		# Return file ID's without JSON
		cleaned_ids = clean_ids(file_id)
	
		output = BytesIO() # output is a "virtual" file. Holds FULL Metascan results.
		
		# Pass in the cleaned ID's and try to retrieve results from metascan.
		# The final_result will give us a status string.
		final_result = scan_results(cleaned_ids, output)
	
		# First thing we do is check to see if we had scan errors,
		# If we did, we don't attach any Metascan information.
		# Just change the subject to inform the user.
		if final_result == 'Did Not Finish':
			email['subject'] = '[Did Not Finish] - ' + orig_subject
			send_message(email)
		
		# Here we know that scan results were successful, and we attach metascan.txt
		# In python emails are MIME data types, so we create a new one,
		# put the output text file as binary data, encode and attach to the email.
		msg = MIMEBase('application', "octet-stream")
		msg.set_payload(output.getvalue())
		msg.add_header('Content-Disposition', 'attachment', filename='metascan.txt')
		encode_base64(msg)
		email.attach(msg)
		
		# Change subject and send.
		if final_result == 'Clean':
			del email['subject']
			email['subject'] = '[Clean] - ' + orig_subject
			send_message(email)
			
		elif final_result == 'Infected':
			del email['subject']
			email['subject'] = '[Infected] - ' + orig_subject
			send_message(email)
		
		elif final_result == 'Scan Error':
			del email['subject']
			email['subject'] = '[Scan Error] - ' + orig_subject
			send_message(email)
		
		return
		
def main():
	
	server = CustomSMTPServer((LISTEN_ON, LISTEN_ON_PORT), None)
	
	asyncore.loop(timeout=0, use_poll=False, map=None, count=None)

	return

# Mimics a C-Like structure. Contains attachment file name and binary data.
# A Tuple could be used here instead.
class name_and_data:
	def __init__(self):
		self.name = None
		self.data = None
		
# This will scan the email object for attachments. If there is an attachment,
# it will return a queue with 1 or more attachments.
def find_attachments(email):

	attachQueue = Queue.Queue()
	# Going through the different parts of the email.
	for email in email.walk():
		if email.is_multipart():
			continue
			
		fileName = email.get_filename() # Stores attachment filename.
		
		if fileName == None: # Sometimes picks up things it shouldn't.
			continue
		
		# We have hit a valid attachment.
		# Here a name_and_data "structure" will be used to hold the attachment name and binary data.
		else:
			attachment = name_and_data()
			attachment.name = str(fileName)
			attachment.data = email.get_payload(decode = 1)
			attachQueue.put(attachment) # Add the name_and_data structure to the queue.
	
	return attachQueue
	
def scan_attachments(filesToScan): 

	responseList = [] # temporary file ID holder.
	
	while filesToScan.empty() == False:
		attachment = filesToScan.get() # Automatically pop/dequeue first attachment.
		
		# Use urllib2 (similar to curl) to send data to MetaScan. 
		request = urllib2.Request(META_SCAN_API_LINK, attachment.data)
		request.add_header('apikey', META_SCAN_API_KEY)
		request.add_header('filename', attachment.name)
		
		# Try the request, if error will return empty list.
		try:
			response = urllib2.urlopen(request)
			
		# Why have responseList twice below? The list will be empty and we know something went wrong.
		# Also if code is used in production environment in the future, one can edit it
		# more easily to do other things based on the error type.
		except URLError as error:
		
			if hasattr(error, 'reason'): # Couldn't contact server.
				responseList[:] = [] # Empty list in case, file before was successful.
				return responseList
				
			elif hasattr(error, 'code'): # Server error.
				responseList[:] = [] # Empty list in case, file before was successful.
				return responseList
				
		# No errors scanning file, append the ID to the list.
		responseList.append(response.read())
		
	return responseList

# The given file id(s) are in JSON format. Need to extract just the id, so we can use string
# manipulation. This will give us a raw string and place it into our list of id(s).
# Can also use python JSON parse here if needed.
def clean_ids(file_id):

	index = 0
	
	while index < len(file_id):
		tempString = file_id[index]
		loc1 = tempString.find(': \"')
		loc2 = tempString.find('\" }')
		file_id[index] = tempString[loc1 + 3: loc2]
		index = index + 1
		
	return file_id

# The scan results are in JSON format. Here I extracted them using python's built-in
# libraries for dealing with JSON as the results were much more work to parse manually.
def scan_results(cleaned_ids, output):

	status = 'Clean'
	
	for id_string in cleaned_ids:
		request = urllib2.Request(META_SCAN_API_LINK + '/' + id_string)
		request.add_header('apikey', META_SCAN_API_KEY)

		# Prime the read request.
		# Take raw data from MetaScan response and convert it to python readable JSON.
		json_results = urllib2.urlopen(request).read()
		decoded_json = json.loads(json_results)
		progress = decoded_json['scan_results']['progress_percentage'] # Get progress percentage from json data.
		
		# May behave different on different systems using time, can always
		# switch to tracking progress only instead of time, i.e. while progress < 100
		# I did it like this in case progress gets stalled at say 90%, that means
		# we had a problem scanning the file.
		timeCount = time.time()
		time.clock()
		elapsed = 0

		while elapsed < SCAN_MAX_LOOKUP_TIME: # Check time elapsed.
			elapsed = time.time() - timeCount # Can be placed at top or bottom of loop.
	
			json_results = urllib2.urlopen(request).read()
			decoded_json = json.loads(json_results)

			progress = decoded_json['scan_results']['progress_percentage'] # Get progress percentage from json data.
			
			if progress == 100: # break early if needed.
				break;
				
			time.sleep(SCAN_LOOKUP_SLEEP_TIME) # Wait X seconds until scan re-check, don't want to flood server :)

		print >>output, str(json.dumps(decoded_json, sort_keys=True, indent=4))# Append to virtual text file.
		
		if progress == 100: # Metascan satisfied requirements.
			# Return a string to figure out what to do to the email.
			result_i = decoded_json['scan_results']['scan_all_result_i']
			if status == 'Infected': # To not overwrite results of infection
				None
			else:
				status = return_scan_value(result_i)
		elif progress < 100: # Scan did not finish in time.
				status = 'Did Not Finish'
				return status
				
	return status

def return_scan_value(x): # Just a quick way to figure out what happened.
	if x == 0 or x == 4 or x == 7:
		return "Clean"
	elif x == 1 or x == 2 or x == 8 or x == 6: # don't know if 6 & 8 should be here.
		return "Infected"
	else: # Could also be split up to be more categories if needed.
		return "Scan Error"
	
	
def send_message(finalMessage):
	
	smtpSend = smtplib.SMTP(MAIL_SERVER_DEST, MAIL_SERVER_PORT)
	smtpSend.sendmail(finalMessage['From'], finalMessage['To'], finalMessage.__str__())  
	return
	
if __name__ == "__main__":
    main()