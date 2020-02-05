/*
 * Amazon FreeRTOS V201906.00 Major
 * Copyright (C) 2019 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#if !defined(MBEDTLS_X509_CSR_WRITE_C) || !defined(MBEDTLS_FS_IO) ||  \
    !defined(MBEDTLS_PK_PARSE_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) || \
    !defined(MBEDTLS_PEM_WRITE_C)
void vGenerateProcedure( void )
{
    configPRINTF( ( "MBEDTLS_X509_CSR_WRITE_C and/or MBEDTLS_FS_IO and/or "
            "MBEDTLS_PK_PARSE_C and/or MBEDTLS_SHA256_C and/or "
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C "
            "not defined.\n" ) );
}
#else
/* mbedtls includes. */
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"

/* server CAs and key information includes. */
#include "aws_clientcredential_keys.h"
#include "aws_iot_key_gen.h"
#include "aws_jitr_config.h"

/* mbedtls defines. */
#define DFL_TYPE                MBEDTLS_PK_RSA
#define DFL_RSA_KEYSIZE         2048
#define DFL_MD_ALG              MBEDTLS_MD_SHA256
#define DFL_RSA_KEYLENGTH       2048
#define DFL_RSA_REQLENGTH       2048
#define DFL_RSA_CRTLENGTH       2048

/* DSN defines. */
#define MAC_ADDR_LENGTH         6
#define DSN_LENGTH              16

mbedtls_entropy_context gEntropy;
mbedtls_ctr_drbg_context gCtr_drbg;

void vGenerateProcedure( void * pArgument )
{
    int ret = 0;
    const char *pers = "gen_key_cert";
    mbedtls_pk_context key;
    mbedtls_x509write_csr req;
    mbedtls_x509write_cert crt;
    mbedtls_x509_crt issuer_crt;
    mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context *issuer_key = &loaded_issuer_key,
                *subject_key = &loaded_subject_key;
    char issuer_name[256];
    char subject_name[256];
    mbedtls_x509_csr csr;
    mbedtls_mpi serial;
    uint8_t mac[MAC_ADDR_LENGTH];
    char mac_adr[DSN_LENGTH];
    devCertificateKeyContext_t * pContext = ( devCertificateKeyContext_t * ) pArgument;

    mbedtls_ctr_drbg_init( &gCtr_drbg );
    mbedtls_entropy_init( &gEntropy );
    mbedtls_pk_init( &key );
    mbedtls_x509write_crt_init( &crt );
    mbedtls_pk_init( &loaded_issuer_key );
    mbedtls_pk_init( &loaded_subject_key );
    mbedtls_mpi_init( &serial );
    mbedtls_x509_csr_init( &csr );
    mbedtls_x509_crt_init( &issuer_crt );

    /* Generate random seed */
    if ( mbedtls_ctr_drbg_seed( &gCtr_drbg, mbedtls_entropy_func, &gEntropy,
                                        ( const unsigned char *) pers,
                                        strlen( pers ) ) != 0 )
    {
        configPRINTF( ( " . Seeding the random number generator failed ...\n" ) );
        goto exit;
    }

    /* Generate device key */
    configPRINTF( ( " . Generating device private key ...\n" ) );
    if( mbedtls_pk_setup( &key, mbedtls_pk_info_from_type( DFL_TYPE ) ) != 0 )
    {
        configPRINTF( ( " . mbedtls_pk_setup failed ...\n" ) );
        goto exit;
    }

    if ( mbedtls_rsa_gen_key( mbedtls_pk_rsa( key ), 
                                mbedtls_ctr_drbg_random, &gCtr_drbg,
                                DFL_RSA_KEYSIZE, 65537 ) != 0 )
    {
        configPRINTF( ( " . mbedtls_rsa_gen_key failed ...\n" ) );
        goto exit;
    }

    mbedtls_pk_write_key_pem( &key, pContext->pcJITRClientPrivateKey, DFL_RSA_KEYLENGTH );

    /* Generate temporary csr */
    mbedtls_x509write_csr_init( &req );

    configPRINTF( ( " . Generating temporary csr ...\n" ) );

    mbedtls_x509write_csr_set_md_alg( &req, DFL_MD_ALG );
    if( mbedtls_x509write_csr_set_subject_name( &req, DFL_SUBJECT_NAME ) != 0 )
    {
        configPRINTF( ( " . mbedtls_x509write_csr_set_subject_name failed ...\n" ) );
        goto exit;
    }

    mbedtls_x509write_csr_set_key( &req, &key );

    if( mbedtls_x509write_csr_pem( &req, pContext->pcJITRClientTempRequest, DFL_RSA_REQLENGTH, 
                                    mbedtls_ctr_drbg_random, &gCtr_drbg ) < 0 )
    {   
        configPRINTF( ( " . mbedtls_x509write_csr_pem failed ...\n" ) );
        goto exit;
    }

    /* Generate device certificate */
    configPRINTF( ( " . Generating device certificate ...\n" ) );

    /* Get Wi-Fi MAC address as device serial number(DSN). */
    if ( esp_read_mac( mac, ESP_MAC_WIFI_STA ) == 0 )
    {
        snprintf( mac_adr, sizeof( mac_adr ), "%02X%02X%02X%02X%02X%02X",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );

        configPRINTF( ( "MAC : %s\n", mac_adr ) );
    }
    else
    {
        configPRINTF( ( " . get mac address failed ...\n" ) );
        goto exit;
    }

    if( mbedtls_mpi_read_string( &serial, 16, mac_adr ) != 0 )
    {
        configPRINTF( ( " . mbedtls_mpi_read_string failed ...\n" ) );
        goto exit;
    }

    if( mbedtls_x509_crt_parse( &issuer_crt, 
        ( const unsigned char * ) keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM, 
        sizeof( keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM ) ) != 0 )
    {
        configPRINTF( ( " . mbedtls_x509_crt_parse issuer_crt failed ...\n" ) );
        goto exit;
    }

    if( mbedtls_x509_dn_gets( issuer_name, sizeof( issuer_name ), &issuer_crt.subject ) < 0 )
    {
        configPRINTF( ( " . mbedtls_x509_dn_gets issuer_name failed ...\n" ) );
        goto exit;
    }

    if( mbedtls_x509_csr_parse( &csr, ( const unsigned char * ) pContext->pcJITRClientTempRequest, 
                            strlen( ( const char * ) pContext->pcJITRClientTempRequest ) + 1 ) != 0 )
    {
        configPRINTF( ( " . mbedtls_x509_csr_parse failed ...\n" ) );
        goto exit;
    }

    if ( mbedtls_x509_dn_gets( subject_name, sizeof(subject_name), &csr.subject ) < 0 )
    {
        configPRINTF( ( " . mbedtls_x509_dn_gets subject_name failed ...\n" ) );
        goto exit;
    }

    subject_key = &csr.pk;
    if ( mbedtls_pk_parse_key( &loaded_issuer_key, 
                (const unsigned char * ) keyJITR_DEVICE_CERTIFICATE_AUTHORITY_KEY_PEM, 
                sizeof( keyJITR_DEVICE_CERTIFICATE_AUTHORITY_KEY_PEM ), NULL, 0 ) != 0 )
    {
        configPRINTF( ( " . mbedtls_pk_parse_key issuer_key failed ...\n" ) );
        goto exit;
    }

    if( mbedtls_pk_check_pair( &issuer_crt.pk, issuer_key ) != 0 )
    {
        configPRINTF( ( " . mbedtls_pk_check_pair failed ...\n" ) );
        goto exit;
    }

    mbedtls_x509write_crt_set_subject_key( &crt, subject_key );
    mbedtls_x509write_crt_set_issuer_key( &crt, issuer_key );

    if( mbedtls_x509write_crt_set_subject_name( &crt, subject_name ) != 0 )
    {
        configPRINTF( ( " . mbedtls_x509write_crt_set_subject_name failed ...\n" ) );
        goto exit;
    }

    if( mbedtls_x509write_crt_set_issuer_name( &crt, issuer_name ) != 0 )
    {
        configPRINTF( ( " . mbedtls_x509write_crt_set_issuer_name failed ...\n" ) );
        goto exit;
    }

    mbedtls_x509write_crt_set_version( &crt, 2 );
    mbedtls_x509write_crt_set_md_alg( &crt, MBEDTLS_MD_SHA256 );

    if( mbedtls_x509write_crt_set_serial( &crt, &serial ) != 0 )
    {
        configPRINTF( ( " . mbedtls_x509write_crt_set_serial failed ...\n" ) );
        goto exit;
    }

    if( mbedtls_x509write_crt_set_validity( &crt, DFL_NOT_BEFORE, DFL_NOT_AFTER ) != 0 )
    {
        configPRINTF( ( " . mbedtls_x509write_crt_set_validity failed ...\n" ) );
        goto exit;
    }

    if( mbedtls_x509write_crt_set_basic_constraints( &crt, 0, -1 ) != 0 )
    {
        configPRINTF( ( " . mbedtls_x509write_crt_set_basic_constraints failed ...\n" ) );
        goto exit;
    }

    if( mbedtls_x509write_crt_set_subject_key_identifier( &crt ) != 0 )
    {
        configPRINTF( ( " . mbedtls_x509write_crt_set_subject_key_identifier failed ...\n" ) );
        goto exit;
    }

    if( mbedtls_x509write_crt_set_authority_key_identifier( &crt ) != 0 )
    {
        configPRINTF( ( " . mbedtls_x509write_crt_set_authority_key_identifier failed ...\n" ) );
        goto exit;
    }

    if( ( ret = mbedtls_x509write_crt_pem( &crt, pContext->pcJITRClientCertificate, DFL_RSA_CRTLENGTH, 
                mbedtls_ctr_drbg_random, &gCtr_drbg ) ) < 0 )
    {
        configPRINTF( ( " . mbedtls_x509write_crt_pem failed ...\n" ) );
        goto exit;
    }

exit:

    mbedtls_ctr_drbg_free( &gCtr_drbg );
    mbedtls_entropy_free( &gEntropy );
    mbedtls_pk_free( &key );
    mbedtls_x509write_csr_free( &req );
    mbedtls_x509_csr_free( &csr );
    mbedtls_x509_crt_free( &issuer_crt );
    mbedtls_pk_free( &loaded_subject_key );
    mbedtls_pk_free( &loaded_issuer_key );
    mbedtls_mpi_free( &serial );
}
#endif /* MBEDTLS_X509_CSR_WRITE_C && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_PEM_WRITE_C */
