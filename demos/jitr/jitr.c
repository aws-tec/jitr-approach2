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

#include <stdio.h>
#include <string.h>

#include "aws_clientcredential_keys.h"
#include "platform/iot_threads.h"
#include "platform/iot_clock.h"

/* MQTT include. */
#include "iot_mqtt.h"

/* MQTT defines. */
#ifndef IOT_DEMO_MQTT_PUBLISH_BURST_SIZE
    #define IOT_DEMO_MQTT_PUBLISH_BURST_SIZE     ( 10 )
#endif
#ifndef IOT_DEMO_MQTT_PUBLISH_BURST_COUNT
    #define IOT_DEMO_MQTT_PUBLISH_BURST_COUNT    ( 10 )
#endif

#define TOPIC_FILTER_COUNT                       ( 4 )
#define CLIENT_IDENTIFIER_MAX_LENGTH             ( 24 )
#define KEEP_ALIVE_SECONDS                       ( 60 )
#define MQTT_TIMEOUT_MS                          ( 5000 )
#define PUBLISH_RETRY_MS                         ( 1000 )
#define PUBLISH_RETRY_LIMIT                      ( 10 )
#define CLIENT_IDENTIFIER_PREFIX                 "dsn_xx_"
#define PUBLISH_PAYLOAD_FORMAT                   "Hello world %d!"
#define PUBLISH_PAYLOAD_BUFFER_LENGTH            ( sizeof( PUBLISH_PAYLOAD_FORMAT ) + 2 )
#define TOPIC_FILTER_LENGTH                      ( ( uint16_t ) ( sizeof( "jitr/demo/topic/1" ) - 1 ) )
#define MQTT_CONNECT_RETRY_LIMIT                 ( 5 )

int RunJITRDemo( bool awsIotMqttMode,
                 const char * pIdentifier,
                 void * pNetworkServerInfo,
                 void * pNetworkCredentialInfo,
                 const IotNetworkInterface_t * pNetworkInterface );

static int _initializeDemo( void )
{
    int status = EXIT_SUCCESS;
    IotMqttError_t mqttInitStatus = IOT_MQTT_SUCCESS;

    mqttInitStatus = IotMqtt_Init();

    if( mqttInitStatus != IOT_MQTT_SUCCESS )
    {
        /* Failed to initialize MQTT library. */
        status = EXIT_FAILURE;
    }

    return status;
}

static int _establishMqttConnection( bool awsIotMqttMode,
                                     const char * pIdentifier,
                                     void * pNetworkServerInfo,
                                     void * pNetworkCredentialInfo,
                                     const IotNetworkInterface_t * pNetworkInterface,
                                     IotMqttConnection_t * pMqttConnection )
{
    int status = EXIT_SUCCESS;
    int retryCount = 0;
    uint32_t mqtt_backoff_timeout_ms = 1 << 12;
    IotMqttError_t connectStatus = IOT_MQTT_STATUS_PENDING;
    IotMqttNetworkInfo_t networkInfo = IOT_MQTT_NETWORK_INFO_INITIALIZER;
    IotMqttConnectInfo_t connectInfo = IOT_MQTT_CONNECT_INFO_INITIALIZER;
    char pClientIdentifierBuffer[ CLIENT_IDENTIFIER_MAX_LENGTH ] = { 0 };
    uint8_t mac[6];
    char identifier_name[CLIENT_IDENTIFIER_MAX_LENGTH];

    /* Set the members of the network info not set by the initializer. This
     * struct provided information on the transport layer to the MQTT connection. */
    networkInfo.createNetworkConnection = true;
    networkInfo.u.setup.pNetworkServerInfo = pNetworkServerInfo;
    networkInfo.u.setup.pNetworkCredentialInfo = pNetworkCredentialInfo;
    networkInfo.pNetworkInterface = pNetworkInterface;

    /* Set the members of the connection info not set by the initializer. */
    connectInfo.awsIotMqttMode = awsIotMqttMode;
    connectInfo.cleanSession = true;
    connectInfo.keepAliveSeconds = KEEP_ALIVE_SECONDS;

    /* Use mac address "dsn_xx_0123456789ab" format as
     * unique client identifier(i.e. thing name). */
    if ( esp_read_mac( mac, ESP_MAC_WIFI_STA ) == 0 )
    {
        status = snprintf( identifier_name, sizeof( identifier_name ), 
                           CLIENT_IDENTIFIER_PREFIX "%02x%02x%02x%02x%02x%02x",
                           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );

        if (status < 0)
        {
            configPRINTF( ( "Failed to generate unique client identifier for demo.\n" ) );
            status = EXIT_FAILURE;
            return status;
        }

        connectInfo.pClientIdentifier = identifier_name;
        connectInfo.clientIdentifierLength = ( uint16_t ) strlen( identifier_name );
        status = EXIT_SUCCESS;
    }
    else
    {
        status = EXIT_FAILURE;
        return status;
    }

    /* Establish the MQTT connection. */
    if( status == EXIT_SUCCESS )
    {
        configPRINTF( ( "JITR demo client identifier is %.*s (length %hu).\n",
                    connectInfo.clientIdentifierLength,
                    connectInfo.pClientIdentifier,
                    connectInfo.clientIdentifierLength ) );

        /* Retry 5 times and do a exponential backoff timeout. */
        do 
        {
            if ( retryCount > MQTT_CONNECT_RETRY_LIMIT )
            {
                configPRINTF( ( "Hit maximum retry count. Error on connecting to MQTT\n" ) );
                break;
            }


            connectStatus = IotMqtt_Connect( &networkInfo,
                                             &connectInfo,
                                             mqtt_backoff_timeout_ms,
                                             pMqttConnection );

            mqtt_backoff_timeout_ms <<= 1;
            retryCount += 1;
        }
        while ( connectStatus != IOT_MQTT_SUCCESS );

        if( connectStatus != IOT_MQTT_SUCCESS )
        {
            configPRINTF( ( "MQTT CONNECT returned error %s.\n",
                         IotMqtt_strerror( connectStatus ) ) );

            status = EXIT_FAILURE;
        }
    }

    return status;
}

static int _publishAllMessages( IotMqttConnection_t mqttConnection,
                                const char ** pTopicNames,
                                IotSemaphore_t * pPublishReceivedCounter )
{
    int status = EXIT_SUCCESS;
    intptr_t publishCount = 0;
    IotMqttError_t publishStatus = IOT_MQTT_STATUS_PENDING;
    IotMqttPublishInfo_t publishInfo = IOT_MQTT_PUBLISH_INFO_INITIALIZER;
    char pPublishPayload[ PUBLISH_PAYLOAD_BUFFER_LENGTH ] = { 0 };

    /* Set the common members of the publish info. */
    publishInfo.qos = IOT_MQTT_QOS_1;
    publishInfo.topicNameLength = TOPIC_FILTER_LENGTH;
    publishInfo.pPayload = pPublishPayload;
    publishInfo.retryMs = PUBLISH_RETRY_MS;
    publishInfo.retryLimit = PUBLISH_RETRY_LIMIT;

    /* Loop to PUBLISH all messages of this demo. */
    for( publishCount = 0; 
         publishCount < IOT_DEMO_MQTT_PUBLISH_BURST_SIZE * IOT_DEMO_MQTT_PUBLISH_BURST_COUNT; 
         publishCount++ )
    {
        /* Announce which burst of messages is being published. */
        if( publishCount % IOT_DEMO_MQTT_PUBLISH_BURST_SIZE == 0 )
        {
            configPRINTF( ( "Publishing messages %d to %d.",
                        publishCount,
                        publishCount + IOT_DEMO_MQTT_PUBLISH_BURST_SIZE - 1 ) );
        }

        /* Choose a topic name (round-robin through the array of topic names). */
        publishInfo.pTopicName = pTopicNames[ publishCount % TOPIC_FILTER_COUNT ];

        /* Generate the payload for the PUBLISH. */
        status = snprintf( pPublishPayload,
                           PUBLISH_PAYLOAD_BUFFER_LENGTH,
                           PUBLISH_PAYLOAD_FORMAT,
                           ( int ) publishCount );

        /* Check for errors from snprintf. */
        if( status < 0 )
        {
            configPRINTF( ( "Failed to generate MQTT PUBLISH payload for PUBLISH %d.\n",
                         ( int ) publishCount ) );
            status = EXIT_FAILURE;

            break;
        }
        else
        {
            publishInfo.payloadLength = ( size_t ) status;
            status = EXIT_SUCCESS;
        }

        /* PUBLISH a message. This is an asynchronous function that notifies of
         * completion through a callback. */
        publishStatus = IotMqtt_Publish( mqttConnection,
                                         &publishInfo,
                                         0,
                                         NULL,
                                         NULL );

        if( publishStatus != IOT_MQTT_STATUS_PENDING )
        {
            configPRINTF( ( "MQTT PUBLISH %d returned error %s.\n",
                         ( int ) publishCount,
                         IotMqtt_strerror( publishStatus ) ) );
            status = EXIT_FAILURE;

            break;
        }
    }

    return status;
}

int RunJITRDemo( bool awsIotMqttMode,
                 const char * pIdentifier,
                 void * pNetworkServerInfo,
                 void * pNetworkCredentialInfo,
                 const IotNetworkInterface_t * pNetworkInterface )
{
    int status = EXIT_SUCCESS;
    bool librariesInitialized = false, connectionEstablished = false;
    IotMqttConnection_t mqttConnection = IOT_MQTT_CONNECTION_INITIALIZER;
    IotSemaphore_t publishesReceived;
    /* Topics used as both topic filters and topic names in this demo. */
    const char * pTopics[ TOPIC_FILTER_COUNT ] =
    {
        "iotdemo/topic/1",
        "iotdemo/topic/2",
        "iotdemo/topic/3",
        "iotdemo/topic/4"
    };

    status = _initializeDemo();

    if( status == EXIT_SUCCESS )
    {
        /* Mark the libraries as initialized. */
        librariesInitialized = true;

        /* Establish a new MQTT connection. */
        status = _establishMqttConnection( awsIotMqttMode,
                                           pIdentifier,
                                           pNetworkServerInfo,
                                           pNetworkCredentialInfo,
                                           pNetworkInterface,
                                           &mqttConnection );
    }

    if( status == EXIT_SUCCESS )
    {
        /* Mark the MQTT connection as established. */
        connectionEstablished = true;

        if( IotSemaphore_Create( &publishesReceived,
                                 0,
                                 IOT_DEMO_MQTT_PUBLISH_BURST_SIZE ) == true )
        {
            status = _publishAllMessages( mqttConnection, 
                                          pTopics, 
                                          &publishesReceived );

            IotSemaphore_Destroy( &publishesReceived );
        }
        else
        {
            status = EXIT_FAILURE;
        }
    }

    if( connectionEstablished == true )
    {
        IotMqtt_Disconnect( mqttConnection, 0 );
    }

    if( librariesInitialized == true )
    {
        IotMqtt_Cleanup();
    }

    return status;
}
