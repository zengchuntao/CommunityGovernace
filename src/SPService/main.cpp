#include <iostream>
#include "SPService/service.h"

#ifndef _WIN32
#include "Common/config.h"
#endif
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
#include <intrin.h>
#include <openssl/applink.c>
#include "win32/getopt.h"
#else
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "Common/common.h"
#include "Common/fileio.h"
#include "Common/crypto.h"
#include "Common/iasrequest.h"
#include "Common/logfile.h"
#include "Common/settings.h"
#include "Common/hexutil.h"
using namespace std;

#include <map>
#include <string>
#include <iostream>
#include <algorithm>

#ifdef _WIN32
#define strdup(x) _strdup(x)
#endif

static const unsigned char def_service_private_key[32] = {
	0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

void usage ();
int get_proxy(char **server, unsigned int *port, const char *url);
int parse_config(int argc, char* argv[], SPConfigStruct& config, char** port);

int main(int argc, char* argv[]) {
    SPConfigStruct config;
    char* port = NULL;
    if (parse_config(argc, argv, config, &port) != 0 ) {
        usage();
        exit(1);
    }

    try {
        SPServiceImpl spservice(&config);
        std::string address("0.0.0.0:");
        address += port;

        grpc::ServerBuilder builder;
        builder.AddListeningPort(address, grpc::InsecureServerCredentials());
        builder.RegisterService(&spservice);

        std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
        std::cout << "server listening on port: " << address << std::endl;
        server->Wait();
    }
    catch (...) {
        eprintf("initial wrong!!!\n");
        exit(-1);
    } 
    

    std::cout << "hello world!" << std::endl;
    return 0;
}

int parse_config(int argc, char* argv[], SPConfigStruct& config, char** port) {
    char flag_spid = 0;
	char flag_pubkey = 0;
	char flag_api_key = 0;
	char flag_ca = 0;
	char flag_usage = 0;
	char flag_noproxy= 0;
	char flag_prod= 0;
	char flag_stdio= 0;
	char flag_isv_product_id= 0;
	char flag_min_isvsvn= 0;
	char flag_mrsigner= 0;
	char *sigrl = NULL;
	
	int oops;
	
#ifndef _WIN32
	struct sigaction sact;
#endif
    int debug = 1;
    int verbose = 1;
	/* Command line options */

	static struct option long_opt[] =
	{
		{"ias-signing-cafile",		required_argument,	0, 'A'},
		{"ca-bundle",				required_argument,	0, 'B'},
		{"json-path",				required_argument,	0, 'C'},
		{"no-debug-enclave",		no_argument,		0, 'D'},
		{"list-agents",				no_argument,		0, 'G'},
		{"ias-pri-api-key-file",	required_argument,	0, 'I'},
		{"ias-sec-api-key-file",	required_argument,	0, 'J'},
		{"service-key-file",		required_argument,	0, 'K'},
		{"mrsigner",				required_argument,  0, 'N'},
		{"production",				no_argument,		0, 'P'},
		{"isv-product-id",			required_argument,	0, 'R'},
		{"spid-file",				required_argument,	0, 'S'},
		{"min-isv-svn",				required_argument,  0, 'V'},
		{"strict-trust-mode",		no_argument,		0, 'X'},
		{"debug",					no_argument,		0, 'd'},
		{"user-agent",				required_argument,	0, 'g'},
		{"help",					no_argument, 		0, 'h'},
		{"ias-pri-api-key",			required_argument,	0, 'i'},
		{"ias-sec-api-key",			required_argument,	0, 'j'},
		{"key",						required_argument,	0, 'k'},
		{"linkable",				no_argument,		0, 'l'},
		{"proxy",					required_argument,	0, 'p'},
		{"api-version",				required_argument,	0, 'r'},
		{"spid",					required_argument,	0, 's'},
		{"verbose",					no_argument,		0, 'v'},
		{"no-proxy",				no_argument,		0, 'x'},
		{"stdio",					no_argument,		0, 'z'},
		{ 0, 0, 0, 0 }
	};

    /* Create a logfile to capture debug output and actual msg data */

	fplog = create_logfile("sp.log");
	fprintf(fplog, "Server log started\n");

	/* Config defaults */

	memset(&config, 0, sizeof(config));

	config.apiver= IAS_API_DEF_VERSION;

	/*
	 * For demo purposes only. A production/release enclave should
	 * never allow debug-mode enclaves to attest.
	 */
	config.allow_debug_enclave= 1;

	/* Parse our options */

	while (1) {
		int c;
		int opt_index = 0;
		off_t offset = IAS_SUBSCRIPTION_KEY_SIZE;
		int ret = 0;
		char *eptr= NULL;
		unsigned long val;

		c = getopt_long(argc, argv,
			"A:B:C:DGI:J:K:N:PR:S:V:X:dg:hk:lp:r:s:i:j:vxz",
			long_opt, &opt_index);
		if (c == -1) break;

		switch (c) {

		case 0:
			break;

		case 'A':
			if (!cert_load_file(&config.signing_ca, optarg)) {
				crypto_perror("cert_load_file");
				eprintf("%s: could not load IAS Signing Cert CA\n", optarg);
				return 1;
			}

			config.store = cert_init_ca(config.signing_ca);
			if (config.store == NULL) {
				eprintf("%s: could not initialize certificate store\n", optarg);
				return 1;
			}
			++flag_ca;

			break;

		case 'B':
			config.ca_bundle = strdup(optarg);
			if (config.ca_bundle == NULL) {
				perror("strdup");
				return 1;
			}

			break;

		case 'D':
			config.allow_debug_enclave= 0;
			break;
		case 'G':
			ias_list_agents(stdout);
			return 1;

		case 'I':
			// Get Size of File, should be IAS_SUBSCRIPTION_KEY_SIZE + EOF
			ret = from_file(NULL, optarg, &offset); 

			if ((offset != IAS_SUBSCRIPTION_KEY_SIZE+1) || (ret == 0)) {
				eprintf("IAS Primary Subscription Key must be %d-byte hex string.\n",
					IAS_SUBSCRIPTION_KEY_SIZE);
				return 1;
			}

			// Remove the EOF
			offset--;

			// Read the contents of the file
			if (!from_file((unsigned char *)&config.pri_subscription_key, optarg, &offset)) {
				eprintf("IAS Primary Subscription Key must be %d-byte hex string.\n",
					IAS_SUBSCRIPTION_KEY_SIZE);
					return 1;
			}
			break;

		case 'J':
			// Get Size of File, should be IAS_SUBSCRIPTION_KEY_SIZE + EOF
			ret = from_file(NULL, optarg, &offset);

			if ((offset != IAS_SUBSCRIPTION_KEY_SIZE+1) || (ret == 0)) {
				eprintf("IAS Secondary Subscription Key must be %d-byte hex string.\n",
					IAS_SUBSCRIPTION_KEY_SIZE);
				return 1;
			}

			// Remove the EOF
			offset--;

			// Read the contents of the file
			if (!from_file((unsigned char *)&config.sec_subscription_key, optarg, &offset)) {
				eprintf("IAS Secondary Subscription Key must be %d-byte hex string.\n",
					IAS_SUBSCRIPTION_KEY_SIZE);
					return 1;
			}

			break;

		case 'K':
			if (!key_load_file(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load_file");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
			break;

		case 'N':
			if (!from_hexstring((unsigned char *)&config.req_mrsigner,
				optarg, 32)) {

				eprintf("MRSIGNER must be 64-byte hex string\n");
				return 1;
			}
			++flag_mrsigner;
			break;

        case 'P':
			flag_prod = 1;
			break;

		case 'R':
			eptr= NULL;
			val= strtoul(optarg, &eptr, 10);
			if ( *eptr != '\0' || val > 0xFFFF ) {
				eprintf("Product Id must be a positive integer <= 65535\n");
				return 1;
			}
			config.req_isv_product_id= val;
			++flag_isv_product_id;
			break;

		case 'S':
			if (!from_hexstring_file((unsigned char *)&config.spid, optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;

			break;

		case 'V':
			eptr= NULL;
			val= strtoul(optarg, &eptr, 10);
			if ( *eptr != '\0' || val > (unsigned long) 0xFFFF ) {
				eprintf("Minimum ISV SVN must be a positive integer <= 65535\n");
				return 1;
			}
			config.min_isvsvn= val;
			++flag_min_isvsvn;
			break;

		case 'X':
			config.strict_trust= 1;
			break;

		case 'd':
			debug = 1;
			break;

		case 'g':
			config.user_agent= strdup(optarg);
			if ( config.user_agent == NULL ) {
				perror("malloc");
				return 1;
			}
			break;

		case 'i':
			if (strlen(optarg) != IAS_SUBSCRIPTION_KEY_SIZE) {
				eprintf("IAS Subscription Key must be %d-byte hex string\n",IAS_SUBSCRIPTION_KEY_SIZE);
				return 1;
			}

			strncpy((char *) config.pri_subscription_key, optarg, IAS_SUBSCRIPTION_KEY_SIZE);

			break;

		case 'j':
			if (strlen(optarg) != IAS_SUBSCRIPTION_KEY_SIZE) {
				eprintf("IAS Secondary Subscription Key must be %d-byte hex string\n",
				IAS_SUBSCRIPTION_KEY_SIZE);
				return 1;
			}

			strncpy((char *) config.sec_subscription_key, optarg, IAS_SUBSCRIPTION_KEY_SIZE);

			break;

		case 'k':
			if (!key_load(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
			break;

		case 'l':
			config.quote_type = SGX_LINKABLE_SIGNATURE;
			break;

		case 'p':
			if ( flag_noproxy ) usage();
			if (!get_proxy(&config.proxy_server, &config.proxy_port, optarg)) {
				eprintf("%s: could not extract proxy info\n", optarg);
				return 1;
			}
			// Break the URL into host and port. This is a simplistic algorithm.
			break;

		case 'r':
			config.apiver= atoi(optarg);
			if ( config.apiver < IAS_MIN_VERSION || config.apiver >
				IAS_MAX_VERSION ) {

				eprintf("version must be between %d and %d\n",
					IAS_MIN_VERSION, IAS_MAX_VERSION);
				return 1;
			}
			break;

		case 's':
			if (strlen(optarg) < 32) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			if (!from_hexstring((unsigned char *)&config.spid, (unsigned char *)optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;
			break;

		case 'v':
			verbose = 1;
			break;

		case 'x':
			if ( config.proxy_server != NULL ) usage();
			flag_noproxy=1;
			break;

		case 'z':
			flag_stdio= 1;
			break;
		case 'C':
			config.json_path = new char[strlen(optarg)];
			strcpy(config.json_path, optarg );
			printf("json path: %s\n", optarg);
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	/* We should have zero or one command-line argument remaining */

	argc-= optind;
	if ( argc > 1 ) {
		printf("%s\n", optarg);
		usage();
	}

	/* The remaining argument, if present, is the port number. */

	if ( flag_stdio && argc ) {
		usage();
	} else if ( argc ) {
		*port= strdup(argv[optind]);
	} else {
		*port= strdup(DEFAULT_PORT);
		if ( *port == NULL ) {
			perror("strdup");
			return 1;
		}
	}

    if ( debug ) {
		eprintf("+++ IAS Primary Subscription Key set to '%c%c%c%c........................%c%c%c%c'\n",
			config.pri_subscription_key[0],
        	config.pri_subscription_key[1],
        	config.pri_subscription_key[2],
        	config.pri_subscription_key[3],
        	config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -4 ],
        	config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -3 ],
        	config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -2 ],
        	config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -1 ]
		);

		eprintf("+++ IAS Secondary Subscription Key set to '%c%c%c%c........................%c%c%c%c'\n",
        	config.sec_subscription_key[0],
        	config.sec_subscription_key[1],
        	config.sec_subscription_key[2],
        	config.sec_subscription_key[3],
        	config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -4 ],
        	config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -3 ],
        	config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -2 ],
        	config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -1 ] 
		);
	}


	/* Use the default CA bundle unless one is provided */

	if ( config.ca_bundle == NULL ) {
		config.ca_bundle= strdup(DEFAULT_CA_BUNDLE);
		if ( config.ca_bundle == NULL ) {
			perror("strdup");
			return 1;
		}
		if ( debug ) eprintf("+++ Using default CA bundle %s\n",
			config.ca_bundle);
	}

	/*
	 * Use the hardcoded default key unless one is provided on the
	 * command line. Most real-world services would hardcode the
	 * key since the public half is also hardcoded into the enclave.
	 */

	if (config.service_private_key == NULL) {
		if (debug) {
			eprintf("Using default private key\n");
		}
		config.service_private_key = key_private_from_bytes(def_service_private_key);
		if (config.service_private_key == NULL) {
			crypto_perror("key_private_from_bytes");
			return 1;
		}

	}

	if (debug) {
		eprintf("+++ using private key:\n");
		PEM_write_PrivateKey(stderr, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
		PEM_write_PrivateKey(fplog, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
	}

	if (!flag_spid) {
		eprintf("--spid or --spid-file is required\n");
		flag_usage = 1;
	}

	if (!flag_ca) {
		eprintf("--ias-signing-cafile is required\n");
		flag_usage = 1;
	}

	if ( ! flag_isv_product_id ) {
		eprintf("--isv-product-id is required\n");
		flag_usage = 1;
	}
	
	if ( ! flag_min_isvsvn ) {
		eprintf("--min-isvsvn is required\n");
		flag_usage = 1;
	}
	
	if ( ! flag_mrsigner ) {
		eprintf("--mrsigner is required\n");
		flag_usage = 1;
	}

	if (flag_usage) usage();

    return 0;
}

#define NNL <<endl<<endl<<
#define NL <<endl<<

void usage () 
{
	cerr << "usage: sp [ options ] [ port ]" NL
    "Required:" NL
    "  -A, --ias-signing-cafile=FILE" NL
    "                           Specify the IAS Report Signing CA file." NNL
    "  -N, --mrsigner=HEXSTRING" NL
    "                           Specify the MRSIGNER value of enclaves that" NL
    "                           are allowed to attest. Enclaves signed by" NL
    "                           other signing keys are rejected." NNL
    "  -R, --isv-product-id=INT" NL
    "                           Specify the ISV Product Id for the service." NL
    "                           Only Enclaves built with this Product Id" NL
    "                           will be accepted." NNL
    "  -V, --min-isv-svn=INT" NL
    "                           The minimum ISV SVN that the service provider" NL
    "                           will accept. Enclaves with a lower ISV SVN" NL
    "                           are rejected." NNL
    "Required (one of):" NL
    "  -S, --spid-file=FILE     Set the SPID from a file containg a 32-byte" NL
    "                           ASCII hex string." NNL
    "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string." NNL
    "Required (one of):" NL
    "  -I, --ias-pri-api-key-file=FILE" NL
    "                           Set the IAS Primary Subscription Key from a" NL
    "                           file containing a 32-byte ASCII hex string." NNL
    "  -i, --ias-pri-api-key=HEXSTRING" NL
    "                           Set the IAS Primary Subscription Key from a" NL
    "                           32-byte ASCII hex string." NNL
    "Required (one of):" NL
    "  -J, --ias-sec-api-key-file=FILE" NL
    "                           Set the IAS Secondary Subscription Key from a" NL
    "                           file containing a 32-byte ASCII hex string." NNL
    "  -j, --ias-sec-api-key=HEXSTRING" NL
    "                           Set the IAS Secondary Subscription Key from a" NL
    "                           32-byte ASCII hex string." NNL
    "Optional:" NL
    "  -B, --ca-bundle-file=FILE" NL
    "                           Use the CA certificate bundle at FILE (default:" NL
    "                           " << DEFAULT_CA_BUNDLE << ")" NNL
    "  -D, --no-debug-enclave   Reject Debug-mode enclaves (default: accept)" NNL
    "  -G, --list-agents        List available user agent names for --user-agent" NNL
    "  -K, --service-key-file=FILE" NL
    "                           The private key file for the service in PEM" NL
    "                           format (default: use hardcoded key). The " NL
    "                           client must be given the corresponding public" NL
    "                           key. Can't combine with --key." NNL
    "  -P, --production         Query the production IAS server instead of dev." NNL
    "  -X, --strict-trust-mode  Don't trust enclaves that receive a " NL
    "                           CONFIGURATION_NEEDED response from IAS " NL
    "                           (default: trust)" NNL
    "  -d, --debug              Print debug information to stderr." NNL
    "  -g, --user-agent=NAME    Use NAME as the user agent for contacting IAS." NNL
    "  -k, --key=HEXSTRING      The private key as a hex string. See --key-file" NL
    "                           for notes. Can't combine with --key-file." NNL
    "  -l, --linkable           Request a linkable quote (default: unlinkable)." NNL
    "  -p, --proxy=PROXYURL     Use the proxy server at PROXYURL when contacting" NL
    "                           IAS. Can't combine with --no-proxy" NNL
    "  -r, --api-version=N      Use version N of the IAS API (default: " << to_string(IAS_API_DEF_VERSION) << ")" NNL
    "  -v, --verbose            Be verbose. Print message structure details and" NL
    "                           the results of intermediate operations to stderr." NNL
    "  -x, --no-proxy           Do not use a proxy (force a direct connection), " NL
    "                           overriding environment." NNL
    "  -z  --stdio              Read from stdin and write to stdout instead of" NL
    "                           running as a network server." <<endl;

	::exit(1);
}

// Break a URL into server and port. NOTE: This is a simplistic algorithm.

int get_proxy(char **server, unsigned int *port, const char *url)
{
	size_t idx1, idx2;
	string lcurl, proto, srv, sport;

	if (url == NULL) return 0;

	lcurl = string(url);
	// Make lower case for sanity
	transform(lcurl.begin(), lcurl.end(), lcurl.begin(), ::tolower);

	idx1= lcurl.find_first_of(":");
	proto = lcurl.substr(0, idx1);
	if (proto == "https") *port = 443;
	else if (proto == "http") *port = 80;
	else return 0;

	idx1 = lcurl.find_first_not_of("/", idx1 + 1);
	if (idx1 == string::npos) return 0;
	
	idx2 = lcurl.find_first_of(":", idx1);
	if (idx2 == string::npos) {
		idx2 = lcurl.find_first_of("/", idx1);
		if (idx2 == string::npos) srv = lcurl.substr(idx1);
		else srv = lcurl.substr(idx1, idx2 - idx1);
	}
	else {
		srv= lcurl.substr(idx1, idx2 - idx1);
		idx1 = idx2+1;
		idx2 = lcurl.find_first_of("/", idx1);

		if (idx2 == string::npos) sport = lcurl.substr(idx1);
		else sport = lcurl.substr(idx1, idx2 - idx1);

		try {
			*port = (unsigned int) ::stoul(sport);
		}
		catch (...) {
			return 0;
		}
	}

	try {
		*server = new char[srv.length()+1];
	}
	catch (...) {
		return 0;
	}

	memcpy(*server, srv.c_str(), srv.length());
	(*server)[srv.length()] = 0;

	return 1;
}

