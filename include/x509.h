#ifndef _X509_
#define _X509_

int verify_x509_cert(unsigned char *cert, int cert_len, char* ca_x509_path);

#endif