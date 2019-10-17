
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "string_utilities.h"
#include "mms_client_connection.h"

static void
print_help()
{
    printf("MMS utility (libiec61850 v0.5) options:\n");
    printf("-h <hostname> specify hostname\n");
    printf("-p <port> specify port\n");
    printf("-l <max_pdu_size> specify maximum PDU size\n");
    printf("-d show list of MMS domains\n");
    printf("-i show server identity\n");
    printf("-t <domain_name> show domain directory\n");
}

int main(int argc, char** argv) {

	char* hostname = copyString("localhost");
	int tcpPort = 102;
	int maxPduSize = 65000;

	char* domainName = NULL;

	int readDeviceList = 0;
	int getDeviceDirectory = 0;
	int identifyDevice = 0;

	int c;

	while ((c = getopt(argc, argv, "idh:p:l:t:")) != -1)
		switch (c) {
		case 'h':
			hostname = copyString(optarg);
			break;
		case 'p':
			tcpPort = atoi(optarg);
			break;
		case 'l':
			maxPduSize = atoi(optarg);
			break;
		case 'd':
			readDeviceList = 1;
			break;
		case 'i':
		    identifyDevice = 1;
		    break;
		case 't':
			getDeviceDirectory = 1;
			domainName = copyString(optarg);
			break;
		default:
		    print_help();
			return 0;
		}

	MmsConnection con = MmsConnection_create();

	MmsError error;

	/* Set maximum MMS PDU size (local detail) to 2000 byte */
	MmsConnection_setLocalDetail(con, maxPduSize);

	if (!MmsConnection_connect(con, &error, hostname, tcpPort)) {
		printf("MMS connect failed!\n");
		goto exit;
	}
	else
		printf("MMS connected.\n");

	if (identifyDevice) {
	    MmsServerIdentity* identity =
	            MmsConnection_identify(con, &error);

	    if (identity != NULL) {
	        printf("\nServer identity:\n----------------\n");
	        printf("  vendor:\t%s\n", identity->vendorName);
	        printf("  model:\t%s\n", identity->modelName);
	        printf("  revision:\t%s\n", identity->revision);
	    }
	    else
	        printf("Reading server identity failed!\n");
	}

	if (readDeviceList) {
		printf("\nDomains present on server:\n--------------------------\n");
		LinkedList nameList = MmsConnection_getDomainNames(con, &error);
		LinkedList_printStringList(nameList);
		LinkedList_destroy(nameList);
	}

	if (getDeviceDirectory) {
		LinkedList variableList = MmsConnection_getDomainVariableNames(con, &error,
				domainName);

		LinkedList element = variableList;

		printf("\nMMS domain variables for domain %s\n", domainName);

		while ((element = LinkedList_getNext(element)) != NULL) {
			char* name = (char*) element->data;

			if (strchr(name, '$') == NULL)
				printf("  %s\n", name);
		}

	}

exit:
	MmsConnection_destroy(con);
}

