import json


def read(message):
    #parsing function
    if message['data']['update_type'] == 'X509LogEntry':
        print("x509 Log Entry")
    else:
        print("Precert Log Entry")

    print("Certificate index: " + str(message['data']['cert_index']))
    print("Certificate link: " + message['data']['cert_link'])
    print("Chain:")
    index = 0
    for i in message['data']['chain']:
        print("\t" + str(index) + ".")
        print("\tSerial: " + i['serial_number'])
        print("\tSubject: " + i['subject']['CN'])
        print("\tKey usage: " + i['extensions']['keyUsage'])
        index += 1

    # print leaf cert
    print("Domains: ", end="")
    for domain in message['data']['leaf_cert']['all_domains']:
        print(domain, end=" ")
    print()
    print("Authority info access: ",
          message['data']['leaf_cert']['extensions']['authorityInfoAccess'].replace("\n", ", "))
    print("Basic constrains: ", message['data']['leaf_cert']['extensions']['basicConstraints'])
    print("Key usage: ", message['data']['leaf_cert']['extensions']['keyUsage'])
    # print SCT
    if message['data']['update_type'] == 'X509LogEntry':
        SCT = message['data']['leaf_cert']['extensions']['ctlSignedCertificateTimestamp']
        print("\nSCT:")
        while len(SCT) > 0:
            print(SCT[:50])
            SCT = SCT[50:]
        print()
    print("Source log: ", message['data']['source']['name'], ", ", message['data']['source']['url'])
    print("---------------------------------------------------------------------------------------\n")

