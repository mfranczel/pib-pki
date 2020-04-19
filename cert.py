
import logging
import sys
import certstream
import json
import cert_reader


def cert_handler(message, context):

    logging.debug("Message -> {}".format(message))

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        my_domain=False
        for domain in all_domains:
            if "michalfranczel" in domain:
                my_domain=True
                break

        if my_domain==True:
            with open('my_cert.json', 'r') as file:
                data = json.load(file)
            with open('my_cert.json', 'w') as file:
                data["all"].append(message)
                json.dump(data, file)
            cert_reader.read(message)

        sys.stdout.flush()

print("\'f\' to print certificates from file")
print("\'s\' to monitor for domain \'michalfranczel.tk\'")

selected = input("Enter selected option:")
if selected == 'f':
    file_name = input("Enter file name (must be dump a save from previous monitoring session - default \'my_cert.json\'):")
    if file_name == '':
        file_name = 'my_cert.json'
    with open(file_name, 'r') as file:
        data = json.load(file)
        for message in data['all']:
            cert_reader.read(message)
elif selected == 's':
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
    certstream.listen_for_events(cert_handler,url='wss://certstream.calidog.io/')