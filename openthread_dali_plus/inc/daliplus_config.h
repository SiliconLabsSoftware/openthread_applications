/*******************************************************************************
 * @file daplus_config.h
 * @brief Configuration file for DaliPlus.
 *******************************************************************************
 * # License
 * <b>Copyright 2025 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * SPDX-License-Identifier: Zlib
 *
 * The licensor of this software is Silicon Laboratories Inc.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 *******************************************************************************
 * # Experimental Quality
 * This code has not been formally tested and is provided as-is. It is not
 * suitable for production environments. In addition, this code will not be
 * maintained and there may be no bug maintenance planned for these resources.
 * Silicon Labs may update projects from time to time.
 ******************************************************************************/
#ifndef DALIPLUS_CONFIG_H_
#define DALIPLUS_CONFIG_H_

#define DALIPLUS_THREAD_PANID                         0xABCD
#define DALIPLUS_THREAD_EXTENDED_PANID                { 0xAB, 0xCD, 0xEF, 0x00, \
                                                        0x11, 0x22, 0x33, 0x44 }
#define DALIPLUS_THREAD_NETWORK_CHANNEL               19
#define DALIPLUS_THREAD_NETWORK_NAME                  "DALIPLUS"
#define DALIPLUS_COAP_PORT                            OT_DEFAULT_COAP_PORT
#define DALIPLUS_COAP_SECURE_PORT                     5684
#define DALIPLUS_COAP_URI                             "dali/d"
#define DALIPLUS_COAPS_URI                            "dali/e"
#define DALIPLUS_COAP_BROADCAST_ADDRESS               "ff03::1"
#define DALIPLUS_COAP_ALL_ELIGIBLE_CHANNEL_MASK       0x7FFF800

#define DALIPLUS_BIND_KEY_LENGTH                      16
#define DALIPLUS_BIND_KEY_CONTENT \
  "231d39c1d7cc1ab1aee224cd096db932"
#define DALIPLUS_NONCE_LENGTH                         10
#define DALIPLUS_CBCMAC_LENGTH                        8
#define DALIPLUS_ENCRYPTED_FIELD_LENGTH               17
#define DALIPLUS_MAX_FRAME_LENGTH                     0x3FF
#define DALIPLUS_NDU_FIELD_LENGTH                     8
#define DALIPLUS_INPUT_DEVICE_PSK                     "CREDENT1AL"

#define DALIPLUS_PACKET_NONENCRYPTED                  0xDA
#define DALIPLUS_PACKET_NDU_LENGTH                    0x08
#define DALIPLUS_PACKET_NDU_FORWARD                   0x00
#define DALIPLUS_PACKET_NDU_BACKWARD                  0x80
#define DALIPLUS_PACKET_NDU_DISCOVERY                 0x10
#define DALIPLUS_PACKET_NDU_NETWORK                   0x20
#define DALIPLUS_PACKET_NDU_ACK                       0xC0
#define DALIPLUS_PACKET_NDU_VERSION                   0x02
#define DALIPLUS_PACKET_NDU_BRIDGE_PRIO               0x20
#define DALIPLUS_PACKET_NDU_SYSTEM_ADDR               0x01

#define DALIPLUS_RESPONSE_COAP_ACK                    0
#define DALIPLUS_RESPONSE_EXECUTED_REPLY              1
#define DALIPLUS_RESPONSE_EXECUTED_NO_REPLY           2

#define MAX_FRAME_PER_TEN_SECONDS                     40
#define FRAME_INTERVAL                                250

#define NVM3_DEFAULT_HANDLE                           nvm3_defaultHandle
#define NVM3_STORAGE_COUNT                            7

#define NVM3_UDP_ENCRYPTION_KEY_SLOT                  1
#define NVM3_UDP_ACCESS_PERMISSION_SLOT               2
#define NVM3_UDP_SENDER_ENCRYPTION_KEY_SLOT           3
#define NVM3_UDP_MULTICAST_SCOPE_SLOT                 4
#define NVM3_UDP_MULTICAST_JITTER_SLOT                5
#define NVM3_UDP_104_SUBNET_SLOT                      6
#define NVM3_UDP_SENDER_ID_SLOT                       7
#define NVM3_UDP_FRAME_COUNTER_SLOT                   8

#endif /* DALIPLUS_CONFIG_H_ */
