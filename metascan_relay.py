#! /usr/bin/python3
# Metascan Online Email Relay
# Author: Matthew Ghafary
# Date Published: Nov. 18, 2013
# Date Updated: Jun 07, 2014
# This script is governed by the Metascan Online Plugin agreement.
# Available on http://github.com/mattgaff/MetaScan-Email-Relay

from email.utils import getaddresses
import sys
import configparser
import os, pwd, grp
import queue
import io
import urllib.request, urllib.error, urllib.parse # For POST
import time
import json
from email import *
import smtplib # SMTP Client
import smtpd # SMTP Server
import asyncore
from io import BytesIO
from email.mime.base import MIMEBase
from email.encoders import encode_base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import mimetypes
import hashlib
import logging

# These are needed up here for the config file to assign
# global variables in the main() function.
MAIL_SERVER_DEST = None
MAIL_SERVER_PORT = None
DOMAIN_ACCEPTED = None
META_SCAN_API_LINK = None
META_SCAN_API_KEY = None
SCAN_LOOKUP_SLEEP_TIME = None
SCAN_MAX_LOOKUP_TIME = None
LOGGING_LEVEL = None

# Global logger, paramenters defined in main()
logger = logging.getLogger(__name__)

def drop_privileges(uid_name='nobody', gid_name='nobody'):
    if os.getuid() != 0:
        logger.warning('Already running as non root')
        return

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

class CustomSMTPServer(smtpd.SMTPServer):

    def process_message(self, peer, mailfrom, rcpttos, data):

        logger.info('Received Email from, ' + mailfrom)

        email = message_from_string(data) # Convert Data string into python email.

        orig_subject = email['subject'] # Will use this when we need to modify subject.
        
        # Scan email for attachments. Return Queue of attachments.
        filesToScan = find_attachments(email)
       
        if filesToScan.empty(): # If there are no attachments, just send the email.
                logger.info('No files to scan, sending message.')
                send_message(email, mailfrom, rcpttos)
                return

        # At least one attachment found.
        # Pass the queue of files in, and return the file_id's.
        file_id = scan_attachments(filesToScan)
       
        if not file_id: # Metascan problem, no file_ids.
          del email['subject'] # NEED to delete subject from email, or possible errors.
          email['subject'] = '[Malware scan error] ' + orig_subject
          logger.error('Unable to get file id\'s from attachments, sending anyawys')
          send_message(email, mailfrom, rcpttos)
          return 
       
        # File_IDs were received successfully.
        # Return file ID's without JSON
        #file_id = clean_ids(file_id)
       
        output = BytesIO() # output is a "virtual" file. Holds FULL Metascan results.
        
        # Pass in the cleaned ID's and try to retrieve results from metascan.
        # The final_result will give us a status string.
        file_id = scan_results(file_id)
       
        # First thing we do is check to see if we had scan errors,
        # If we did, we don't attach any Metascan information.
        # Just change the subject to inform the user.
        if file_id == 'Did Not Finish':
          email['subject'] = '[Malware scan error] ' + orig_subject
          logger.error('Scan Error, sending anyways.')
          send_message(email, mailfrom, rcpttos)
        
        final_result = 'Clean'

        for final_list in file_id:
          if return_scan_value(final_list.status) == 'Infected':
            final_result = 'Infected'
          elif return_scan_value(final_list.status) == 'Clean':
            None
          else:
            final_result = 'Scan Error'
          output.write(json.dumps(final_list.json_results, sort_keys=True, indent=4).encode('utf-8'))

        # Here we know that scan results were successful, and we attach metascan.txt
        # In python emails are MIME data types, so we create a new one,
        # put the output text file as binary data, encode and attach to the email.
        msg = MIMEBase('application', "octet-stream")
        msg.set_payload(output.getvalue())
        msg.add_header('Content-Disposition', 'attachment', filename='metascan.txt')
        encode_base64(msg)
        email.attach(msg)

        msg2 = MIMEText("\n\nScanned with Metascan Online\nhttps://www.metascan-online.com", 'plain')

        email.attach(msg2)

        # Change subject and send.
        if final_result == 'Clean':
          del email['subject']
          email['subject'] = '[No threat detected] ' + orig_subject
          send_message(email, mailfrom, rcpttos)
          
        elif final_result == 'Infected':
          del email['subject']
          email['subject'] = '[Threat detected, Attachment(s) removed] ' + orig_subject
          strip_attachment(email, file_id)
          send_message(email, mailfrom, rcpttos)
        
        elif final_result == 'Scan Error':
          del email['subject']
          email['subject'] = '[Malware scan error] ' + orig_subject
          send_message(email, mailfrom, rcpttos)

        return
    
def main():
       # Setup the logger
       logging.basicConfig(format='%(asctime)s, %(levelname)s: %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename='logfile', level=10)

       # global flag needed to allow writing to variables near the top of program
       global DOMAIN_ACCEPTED
       global MAIL_SERVER_DEST
       global MAIL_SERVER_PORT
       global META_SCAN_API_LINK
       global META_SCAN_API_KEY
       global SCAN_LOOKUP_SLEEP_TIME
       global SCAN_MAX_LOOKUP_TIME
       global LOGGING_LEVEL

       logger.info('Reading config file')
       # Here we read the config file and assign variables
       config = configparser.ConfigParser()
       try:
         config.read("config.ini")
         LISTEN_ON              = config.get('default', 'LISTEN_ON')
         LISTEN_ON_PORT         = config.getint('default', 'LISTEN_ON_PORT')
         MAIL_SERVER_DEST       = config.get('default', 'MAIL_SERVER_DEST')
         MAIL_SERVER_PORT       = config.get('default', 'MAIL_SERVER_PORT')
         DOMAIN_ACCEPTED        = config.get('default', 'DOMAIN_ACCEPTED')
         MAX_EMAIL_SIZE         = config.getint('default', 'MAX_EMAIL_SIZE')
         META_SCAN_API_LINK     = config.get('default', 'META_SCAN_API_LINK')
         META_SCAN_API_KEY      = config.get('default', 'META_SCAN_API_KEY')
         SCAN_LOOKUP_SLEEP_TIME = config.getint('default', 'SCAN_LOOKUP_SLEEP_TIME')
         SCAN_MAX_LOOKUP_TIME   = config.getint('default', 'SCAN_MAX_LOOKUP_TIME')
         LOGGING_LEVEL          = config.getint('default', 'LOGGING_LEVEL')
       except:
          # Print and log.
          print('Error occured, check logfile. EXITING....')
          logging.error('CONFIG FILE ERROR: Please check if config.ini is in directory and/or syntax is correct.')
          sys.exit()

       logging.basicConfig(format='%(asctime)s, %(levelname)s: %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename='logfile', level=LOGGING_LEVEL)
       logger.info('Starting server')

       try:
        server = CustomSMTPServer((LISTEN_ON, LISTEN_ON_PORT), None, data_size_limit = (MAX_EMAIL_SIZE * 1048576))
       except:
        print('Error occured, check logfile. EXITING....')
        logging.error('Error starting server, please make sure your system configuration is correct.')
        sys.exit()

       drop_privileges()
       asyncore.loop()
       return

# Mimics a C-Like structure. Contains attachment file name and binary data.
class name_and_data:
       def __init__(self):
        self.name = None
        self.data = None

class id_and_scan:
      def __init__(self):
        self.id = None
        self.scanned_before = None
        self.status = None
        self.json_results = None
        self.sha1_sum = None
        self.file_name = None
        self.rest_ip = None

# This will scan the email object for attachments. If there is an attachment,
# it will return a queue with 1 or more attachments.
def find_attachments(email):

       attachQueue = queue.Queue()
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

        # Get sha1sum of current file, then send sha1 to metascan to see if it has scanned before.
        # If it has scanned before, don't scan it, but still put id in responseList.
        # If it hasn't been scanned, we scan, then put id in responseList.
        sha1sum = hashlib.sha1(attachment.data).hexdigest().upper()
        sha1Final = 'https://hashlookup.metascan-online.com/v2/hash/' + sha1sum
        requestToSeeIfScannedBefore = urllib.request.Request(sha1Final)
        requestToSeeIfScannedBefore.add_header('apikey', META_SCAN_API_KEY)

        json_results = urllib.request.urlopen(requestToSeeIfScannedBefore).read().decode("utf-8")
        decoded_json = json.loads(json_results)

        if('Not Found' == decoded_json.get(sha1sum)): # hasn't been scanned before.
          request = urllib.request.Request(META_SCAN_API_LINK, attachment.data)
          request.add_header('apikey', META_SCAN_API_KEY)
          request.add_header('filename', attachment.name)
          try:
              response = urllib.request.urlopen(request).read().decode("utf-8")
              decoded_response = json.loads(response)

          except:
              logger.error('Problem contacting Metascan server.')
              responseList[:] = [] # Empty list in case, file before was successful.
              return responseList

          # No errors scanning file, append the ID to the list.
          idStruct = id_and_scan()
          idStruct.id = str(decoded_response['data_id'])
          idStruct.rest_ip = str(decoded_response['rest_ip'])
          idStruct.scanned_before = False
          idStruct.sha1_sum = sha1sum
          idStruct.file_name = attachment.name
          responseList.append(idStruct)
        else:
          data_id = decoded_json['data_id']
          idStruct = id_and_scan()
          idStruct.id = data_id
          idStruct.scanned_before = True
          idStruct.status = decoded_json['scan_results']['scan_all_result_i']
          idStruct.sha1_sum = decoded_json['file_info']['sha1']
          idStruct.file_name = decoded_json['file_info']['display_name']
          idStruct.json_results = decoded_json
          responseList.append(idStruct)
        
       return responseList

# The scan results are in JSON format. Here I extracted them using python's built-in
# libraries for dealing with JSON as the results were much more work to parse manually.
def scan_results(cleaned_ids):

       status = 'Clean'
       
       for id_string in cleaned_ids:
        if(id_string.scanned_before == True):
          continue
        
        # Specific file not scanned before. From lookup. Now send it to metascan-online.com
        request = urllib.request.Request('https://' + id_string.rest_ip + '/file/' + id_string.id)
        request.add_header('apikey', META_SCAN_API_KEY)

        # After file sent returns result of data_id and metascan rest URL to use.
        json_results = urllib.request.urlopen(request).read().decode("utf-8")
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
       
          json_results = urllib.request.urlopen(request).read().decode("utf-8")
          decoded_json = json.loads(json_results)

          progress = decoded_json['scan_results']['progress_percentage'] # Get progress percentage from json data.
          
          if progress == 100: # break early if needed.
            break;
            
          time.sleep(SCAN_LOOKUP_SLEEP_TIME) # Wait X seconds until scan re-check, don't want to flood server :)

        if progress == 100:
          id_string.scanned_before = True
          id_string.json_results = decoded_json
          id_string.status = decoded_json['scan_results']['scan_all_result_i']
        elif progress < 100:
          status = 'Did Not Finish'
          return status
            
       return cleaned_ids

def return_scan_value(x): # Just a quick way to figure out what happened.
       if x == 0 or x == 4 or x == 7:
        return "Clean"
       elif x == 1 or x == 2 or x == 8 or x == 6: # don't know if 6 & 8 should be here.
        return "Infected"
       else: # Could also be split up to be more categories if needed.
        return "Scan Error"
       
       
def send_message(finalMessage, mailFrom, rcpttos):

       try:
        smtpSend = smtplib.SMTP(MAIL_SERVER_DEST, MAIL_SERVER_PORT)
        smtpSend.sendmail(mailFrom, rcpttos, finalMessage.__str__())
       except:
        logger.error('COULD NOT SEND EMAIL')
        return

       return

def strip_attachment(email, file_id):

  for part in email.walk():
    if part.is_multipart():
      continue

    fileName = part.get_filename()

    if fileName == None:
      continue

    else:
      temp_attachment = part.get_payload(decode = 1)
      sha1sum = hashlib.sha1(temp_attachment).hexdigest().upper()
      for struct in file_id:
        if(struct.sha1_sum == sha1sum):
          # Dont get [0] because we are chaging it anyways.
          params = part.get_params()[1:]
          # Conver to cleaned up string
          params = ', '.join([ '='.join(p) for p in params ])
          # Just set the payload to an empty string
          part.set_payload("")
          for name, actual in part.get_params()[1:]:
            part.del_param(name)

          part.set_type('text/plain')
          del part['Content-Transfer-Encoding']
          del part['Content-Disposition']

  return

if __name__ == "__main__":
    main()
