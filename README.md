# openssl_sample
Sample app to create a connection to a HTTPS server

Modified from Marty Kalin's example posted on https://opensource.com/article/19/6/cryptography-basics-openssl-part-1

Main change is to fix SSL_CTX_load_verify_locations() to just after the context is created, before BIO_get_ssl(). Reason being verification of certificate chain takes place during connection, and not during SSL_get_verify_result().

Minor changes include option to specify destination address and to suppress output by default
