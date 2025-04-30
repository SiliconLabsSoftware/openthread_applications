/*******************************************************************************
 * @file daliplus.h
 * @brief Header file for DaliPlus.
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
#ifndef DALIPLUS_H_
#define DALIPLUS_H_

#include <string.h>
#include <openthread/thread_ftd.h>
#include <openthread/coap.h>
#include "sl_sleeptimer.h"
#include "daliplus_config.h"

/**
 * Those below data fields are used specifically for this demonstration, kindly
 * refer to actual documentation (IEC 62386:2019 Standard, Part 104 Changes and Additions, etc...)
 * by DiiA for in-depth information about DALI+ (about device role, data frame, etc...).
 * This demonstration complies with Part 104 Changes and Additions.
 */

/**
 * \brief    Error code.
 */
typedef enum {
  DALIPLUS_ERROR_NONE = 0,
  DALIPLUS_ERROR_FAILED,
  DALIPLUS_ERROR_INVALID_ROLE,
  DALIPLUS_ERROR_IP6_NOT_ENABLED,
  DALIPLUS_ERROR_PACKET_TYPE,
  DALIPLUS_ERROR_PACKET_UNDERSIZED,
  DALIPLUS_ERROR_PACKET_OVERSIZED,
  DALIPLUS_ERROR_MESSAGE_INIT,
  DALIPLUS_ERROR_MESSAGE_ENCRYPTION,
  DALIPLUS_ERROR_MESSAGE_URI,
  DALIPLUS_ERROR_MESSAGE_PAYLOAD_MARKER,
  DALIPLUS_ERROR_MESSAGE_APPEND,
  DALIPLUS_ERROR_MESSAGE_SEND,
  DALIPLUS_ERROR_MESSAGE_DECRYPTION,
  DALIPLUS_ERROR_NVM3,
  DALIPLUS_ERROR_MAX_FRAMES
} daliplus_error_t;

/**
 * \brief    Type of packet for delivery
 */
typedef enum {
  DALIPLUS_PACKET_FORWARD = DALIPLUS_PACKET_NDU_FORWARD,
  DALIPLUS_PACKET_DISCOVERY = DALIPLUS_PACKET_NDU_DISCOVERY,
  DALIPLUS_PACKET_NETWORK_CONFIG = DALIPLUS_PACKET_NDU_NETWORK,
  DALIPLUS_PACKET_BACKWARD = DALIPLUS_PACKET_NDU_BACKWARD,
  DALIPLUS_PACKET_ACK_ERROR = DALIPLUS_PACKET_NDU_ACK,
  DALIPLUS_PACKET_ENCRYPTED = 1,
  DALIPLUS_PACKET_ACK
} daliplus_packet_t;

/**
 * \brief    Role of the device
 */
typedef enum {
  DALIPLUS_ROLE_MAIN_DEVICE,
  DALIPLUS_ROLE_SECONDARY_DEVICE,
} daliplus_role_t;

/**
 * \brief    This struct contains device's role, EUI64 and IP6 address
 */
typedef struct {
  daliplus_role_t deviceRole;
  uint8_t deviceEUI64[OT_EXT_ADDRESS_SIZE];
  otIp6Address deviceIP6Address;
} daliplus_device_t;

/**
 * \brief    This struct contains information about the message that is
 *           about to be sent
 */
typedef struct {
  daliplus_packet_t packetType;
  uint8_t *packetContent;
  uint16_t packetLength;
} daliplus_message_t;

/*******************************************************************************
 * @brief
 *  Get the current OpenThread instance.
 *
 * @return              The pointer of the DaliPlus instance
 ******************************************************************************/
otInstance *get_daliplus_instance(void);

/*******************************************************************************
 * @brief
 *  Initialize the DaliPlus device according to its role.
 *
 * @param[in] deviceRole   The role of the device.
 *
 * @return                 DALIPLUS_ERROR_NONE if OK, error code otherwise
 ******************************************************************************/
daliplus_error_t daliplus_init(daliplus_role_t deviceRole);

/*******************************************************************************
 * @brief
 *  Forward a message to the desired address
 *
 * @param[in] isEncrypted         Option to send encrypted message or not.
 *
 * @param[in] targetedAddress     The pointer of the targeted address.
 *
 * @param[in] messageInfo         Pointer to the message that is going to be sent.
 *
 * @return                        DALIPLUS_ERROR_NONE if OK, error code otherwise
 ******************************************************************************/
daliplus_error_t daliplus_forward_coap_message(bool isEncrypted,
                                               otIp6Address *targetedAddress,
                                               daliplus_message_t *messageInfo);

/*******************************************************************************
 * @brief
 *  Broadcast the message for any devices to see.
 *
 * @param[in] isEncrypted         Option to send encrypted message or not.
 *
 * @param[in] messageInfo         Pointer to the message that is going to be sent.
 *
 * @return                        DALIPLUS_ERROR_NONE if OK, error code otherwise
 ******************************************************************************/
daliplus_error_t daliplus_broadcast_coap_message(bool isEncrypted,
                                                 daliplus_message_t *messageInfo);

/*******************************************************************************
 * @brief
 *  Response the forward message by sending various types of backward message
 *
 * @param[in] isEncrypted         Option to send encrypted message or not.
 *
 * @param[in] requestMessage      Request message that the device received first.
 *
 * @param[in] requestMessageInfo  Request message info that the device received first.
 *
 * @param[in] messageInfo         Pointer to the message that is going to be sent.
 *
 * @return                        DALIPLUS_ERROR_NONE if OK, error code otherwise
 ******************************************************************************/
daliplus_error_t daliplus_backward_response(bool isEncrypted,
                                            otMessage *requestMessage,
                                            const otMessageInfo *requestMessageInfo,
                                            daliplus_message_t *messageInfo);

/*******************************************************************************
 * @brief
 *  Decrypt the message.
 *
 * @param[in] key                     Bind key that is used for decryption.
 *
 * @param[in] inputEncryptedMessage   Encrypted message that is used for decryption.
 *
 * @param[in] inputMessageSize        Size of the encrypted message.
 *
 * @param[out] outputDecryptedMessage A pointer to where the
 *                                    decrypted message should be.
 *
 * @param[out] outputDataSize         Size of the decrypted message.
 *
 * @return                            DALIPLUS_ERROR_NONE if OK, error code otherwise
 ******************************************************************************/
daliplus_error_t daliplus_decrypt_message(uint8_t const *const key,
                                          uint8_t *inputEncryptedMessage,
                                          uint16_t inputMessageSize,
                                          uint8_t *outputDecryptedMessage,
                                          uint16_t *outputDataSize);

/*******************************************************************************
 * @brief
 *  Set non-volatile memory related variable.
 *
 * @param[in] slot                    Slot in NVM that contains the variable.
 *
 * @param[in] value                   A pointer to the desired value.
 *
 * @param[in] len                     Size of the data to be written.
 *
 * @return                            DALIPLUS_ERROR_NONE if OK, error code otherwise
 ******************************************************************************/
daliplus_error_t daliplus_set_nvm_var(uint8_t slot, void *value, uint16_t len);

/*******************************************************************************
 * @brief
 *  Read non-volatile memory related variable
 *
 * @param[in]  slot                   Slot in NVM that contains the variable.
 *
 * @param[out] value                  A pointer to where the read data should be.
 *
 * @param[out] len                    Size of the data to be read.
 *
 * @return                            DALIPLUS_ERROR_NONE if OK, error code otherwise
 ******************************************************************************/
daliplus_error_t daliplus_read_nvm_var(uint8_t slot, void *value, uint16_t len);

/*******************************************************************************
 * @brief
 *  Update the NDU Sequence for every device to match, call this after every
 *  successfully received message (Get the NDU value from the message).
 *
 * @param[in] value                   Value to be updated.
 ******************************************************************************/
void update_ndu_sequence(uint16_t value);

/*******************************************************************************
 * @brief
 *  Log the received message (to be replaced later).
 *
 * @param[in] packetType              Type of message that is received.
 *
 * @param[in] packetPayload           Content of the packet to be displayed.
 *
 * @param[in] payloadLength           Length of the payload
 ******************************************************************************/
void daliplus_display_received_message(daliplus_packet_t packetType,
                                       uint8_t *packetPayload,
                                       uint16_t payloadLength);

/*******************************************************************************
 * @brief
 *  Callback whenever there is a change in state (to be replaced later).
 *
 * @param[in]  aFlags                 A bit-field indicating specific state that
 *                                    has changed. See `OT_CHANGED_*` definitions.
 *
 * @param[in]  aContext               A pointer to application-specific context.
 ******************************************************************************/
void netif_state_changed_cb(otChangedFlags aFlags, void *aContext);

/*******************************************************************************
 * @brief
 *  Callback whenever a CoAP request with a given Uri-Path is received
 *  (to be replaced later)
 *
 * @param[in]  aContext      A pointer to arbitrary context information.
 *
 * @param[in]  aMessage      A pointer to the message.
 *
 * @param[in]  aMessageInfo  A pointer to the message info for @p aMessage.
 ******************************************************************************/
void daliplus_request_cb(void *aContext,
                         otMessage *aMessage,
                         const otMessageInfo *aMessageInfo);

/*******************************************************************************
 * @brief
 *  Callback whenever a CoAP response is received or on the request timeout.
 *  (to be replaced later)
 *
 * @param[in]  aContext      A pointer to application-specific context.
 *
 * @param[in]  aMessage      A pointer to the message buffer containing the response.
 *                           NULL if no response was received.
 *
 * @param[in]  aMessageInfo  A pointer to the message info for @p aMessage.
 *                           NULL if no response was received.
 *
 * @param[in]  aResult       A result of the CoAP transaction.
 ******************************************************************************/
void daliplus_response_cb(void *aContext,
                          otMessage *aMessage,
                          const otMessageInfo *aMessageInfo,
                          otError aResult);

/*******************************************************************************
 * @brief
 * Pointer is called during an IEEE 802.15.4 Active Scan when an IEEE 802.15.4 Beacon is received or
 * the scan completes.
 *
 * @param[in]  aResult   A valid pointer to the beacon information or NULL when the active scan completes.
 *
 * @param[in]  aContext  A pointer to application-specific context.
 ******************************************************************************/
void daliplus_scan_cb(otActiveScanResult *aResult, void *aContext);

#endif /* DALIPLUS_H_ */
