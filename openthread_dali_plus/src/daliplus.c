/*******************************************************************************
 * @file daliplus.c
 * @brief DaliPlus source file.
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
#include "../inc/daliplus.h"
#include "nvm3.h"
#include "nvm3_hal_flash.h"
#include "mbedtls/ccm.h"

/*******************************************************************************
 * @brief
 * Check for error whenever a call is made relating to message
 ******************************************************************************/
#define CHECK_THREAD_ERROR(call, error) \
  if ((call) != OT_ERROR_NONE) {        \
    otMessageFree(coapMessage);         \
    return (error);                     \
  }

static mbedtls_ccm_context encryptCtx;  // Context for AES-CCM encryption
static uint16_t daliplusSentFrames = 0;  // Number of sent frames in the span of 10s
static uint32_t daliplusLastResetTime = 0;  // Last reset time
static otInstance *daliplusInstance = NULL;   // DaliPlus' thread instance

static otCoapResource daliplusCoapResource = {
  .mUriPath = DALIPLUS_COAP_URI,
  .mHandler = daliplus_request_cb,
  .mContext = NULL,
  .mNext = NULL
};

// Runtime variables (refer to Part 104 Changes and Additions by DiiA)
static uint16_t udpNduSequenceNumber = 0;  // 16-bit sequence number (reset on reboot)

// These runtime variables are noted in the documents
// but for this demonstration, it is not needed.
// static uint32_t udpActiveAcLifetime[5] = {0};
// static uint8_t udpActiveAcMethod[5] = {0};
// static otIp6Address udpActiveAcAddress[5];

// Persistent variables (refer Part 104 Changes and Additions and IEC Standard for more info)
static uint8_t udpEncryptionKey[DALIPLUS_BIND_KEY_LENGTH] = { 0 }; // 128-bit value encryption keys
static uint8_t udpAccessPermission[8] = { 0 }; // Access permission levels
static uint16_t udpMulticastResponseJitter = 2000;  // Jitter time response: 0ms to 2000ms
static uint16_t udp104Subnet = 0x1234;  // Valid range: 0x0000 to 0xFFFE
static uint16_t udpSenderID = 0x2468;  // Unique ID for the sender
static uint64_t udpFrameCounter = 0;  // 40-bit frame counter
static uint8_t udpSenderEncryptionKey = 0xFF;  // Sender encryption key (0xFF = encryption off)
static uint8_t udpMulticastScope = 4;  // Valid range: 0x03 to 0x0F

/*******************************************************************************
 * @brief
 *  Setup the Thread network
 ******************************************************************************/
static void setup_thread_network(void);

/*******************************************************************************
 * @brief
 *  Setup the main DaliPlus device.
 ******************************************************************************/
static void daliplus_main_device_setup(void);

/*******************************************************************************
 * @brief
 *  Set Thread network parameters.
 ******************************************************************************/
static void thread_network_set_parameters(void);

/*******************************************************************************
 * @brief
 *  Initialize CoAP server.
 ******************************************************************************/
static void coap_init(void);

/*******************************************************************************
 * @brief
 *  Increment the NDU sequence.
 ******************************************************************************/
static void increment_ndu_sequence(bool isEncrypted);

/*******************************************************************************
 * @brief
 *  Initialize all NVM variable.
 ******************************************************************************/
static void daliplus_persistent_var_init(void);

/*******************************************************************************
 * @brief
 *  Check whether it is fine to send a forward frame.
 ******************************************************************************/
static bool can_send_forward_frame(void);

/*******************************************************************************
 * @brief
 *  Build the DaliPlus packet.
 *
 * @param[in] isEncrypted         Option to build the message with encryption or not.
 *
 * @param[in] messageInfo         A pointer to the message information
 *
 * @param[in] outputDataFrame     A pointer to where the built frame should be
 *
 * @return                        DALIPLUS_ERROR_NONE if OK, error code otherwise
 ******************************************************************************/
static daliplus_error_t daliplus_build_packet(bool isEncrypted,
                                              daliplus_message_t *messageInfo,
                                              uint8_t *outputDataFrame);

void sl_ot_create_instance(void)
{
  daliplusInstance = otInstanceInitSingle();
  assert(daliplusInstance);
}

otInstance *get_daliplus_instance(void)
{
  return daliplusInstance;
}

/*******************************************************************************
 * @brief
 *  Initialize the DaliPlus device according to its role.
 ******************************************************************************/
daliplus_error_t daliplus_init(daliplus_role_t deviceRole)
{
  switch (deviceRole)
  {
    case DALIPLUS_ROLE_MAIN_DEVICE:
      daliplus_main_device_setup();
      daliplus_persistent_var_init();
      setup_thread_network();
      coap_init();
      break;

    case DALIPLUS_ROLE_SECONDARY_DEVICE:
      daliplus_persistent_var_init();
      coap_init();
      break;

    default:
      return DALIPLUS_ERROR_INVALID_ROLE;
  }
  return DALIPLUS_ERROR_NONE;
}

/*******************************************************************************
 * @brief
 *  Forward a message to the desired address.
 ******************************************************************************/
daliplus_error_t daliplus_forward_coap_message(bool isEncrypted,
                                               otIp6Address *targetedAddress,
                                               daliplus_message_t *messageInfo)
{
  if (messageInfo->packetLength > DALIPLUS_MAX_FRAME_LENGTH) {
    return DALIPLUS_ERROR_PACKET_OVERSIZED;
  }

  if ((messageInfo->packetType == DALIPLUS_PACKET_BACKWARD)
      || (messageInfo->packetType == DALIPLUS_PACKET_ACK)
      || (messageInfo->packetType == DALIPLUS_PACKET_ACK_ERROR)) {
    return DALIPLUS_ERROR_PACKET_TYPE;
  }
  // Packet content (ADU/CDU/DDU) + 8 NDU bytes
  uint16_t totalLength = messageInfo->packetLength + DALIPLUS_NDU_FIELD_LENGTH;

  // Plus another 18 bytes from the SDU field
  // minus 1 bytes from NDU field (omitted KeyID)
  if (isEncrypted) {
    totalLength += DALIPLUS_ENCRYPTED_FIELD_LENGTH;
  }
  uint8_t daliplusBuffer[totalLength];
  memset(daliplusBuffer, 0, sizeof(daliplusBuffer));

  otMessageInfo coapMessageInfo;
  memset(&coapMessageInfo, 0, sizeof(coapMessageInfo));
  otMessage *coapMessage = otCoapNewMessage(daliplusInstance, NULL);
  if (coapMessage == NULL) {
    return DALIPLUS_ERROR_MESSAGE_INIT;
  }

  // Making the device know where to send
  memcpy(&coapMessageInfo.mPeerAddr, targetedAddress, sizeof(otIp6Address));
  coapMessageInfo.mPeerPort = DALIPLUS_COAP_PORT;

  // Initializes the CoAP header.
  otCoapMessageInit(coapMessage, OT_COAP_TYPE_CONFIRMABLE, OT_COAP_CODE_POST);

  CHECK_THREAD_ERROR(otCoapMessageAppendUriPathOptions(coapMessage,
                                                       DALIPLUS_COAP_URI),
                     DALIPLUS_ERROR_MESSAGE_URI);

  CHECK_THREAD_ERROR(otCoapMessageSetPayloadMarker(coapMessage),
                     DALIPLUS_ERROR_MESSAGE_PAYLOAD_MARKER);

  // Build the packet before sending it
  if (daliplus_build_packet(isEncrypted,
                            messageInfo,
                            daliplusBuffer) != DALIPLUS_ERROR_NONE) {
    return DALIPLUS_ERROR_MESSAGE_ENCRYPTION;
  }

  CHECK_THREAD_ERROR(otMessageAppend(coapMessage, daliplusBuffer, totalLength),
                     DALIPLUS_ERROR_MESSAGE_APPEND);

  // If one device send more than 40 frames per 10s, it shall be barred
  // from sending more for a while
  if (!can_send_forward_frame()) {
    return DALIPLUS_ERROR_MAX_FRAMES;
  }

  CHECK_THREAD_ERROR(otCoapSendRequest(daliplusInstance,
                                       coapMessage,
                                       &coapMessageInfo,
                                       daliplus_response_cb,
                                       daliplusInstance),
                     DALIPLUS_ERROR_MESSAGE_SEND);

  // Increment the NDU sequence every time a device send a new packet
  increment_ndu_sequence(isEncrypted);
  return DALIPLUS_ERROR_NONE;
}

// Broadcast the message for any devices to see.
daliplus_error_t daliplus_broadcast_coap_message(bool isEncrypted,
                                                 daliplus_message_t *messageInfo)
{
  if (messageInfo->packetLength > DALIPLUS_MAX_FRAME_LENGTH) {
    return DALIPLUS_ERROR_PACKET_OVERSIZED;
  }

  if ((messageInfo->packetType == DALIPLUS_PACKET_BACKWARD)
      || (messageInfo->packetType == DALIPLUS_PACKET_ACK)
      || (messageInfo->packetType == DALIPLUS_PACKET_ACK_ERROR)) {
    return DALIPLUS_ERROR_PACKET_TYPE;
  }
  // Packet content (ADU/CDU/DDU) + 8 NDU bytes
  uint16_t totalLength = messageInfo->packetLength + DALIPLUS_NDU_FIELD_LENGTH;

  // Plus another 18 bytes from the SDU field
  // minus 1 bytes from NDU field (omitted KeyID)
  if (isEncrypted) {
    totalLength += DALIPLUS_ENCRYPTED_FIELD_LENGTH;
  }
  uint8_t daliplusBuffer[totalLength];
  memset(daliplusBuffer, 0, sizeof(daliplusBuffer));

  otMessage *coapMessage = otCoapNewMessage(daliplusInstance, NULL);
  otMessageInfo coapMessageInfo;
  memset(&coapMessageInfo, 0, sizeof(coapMessageInfo));
  if (coapMessage == NULL) {
    return DALIPLUS_ERROR_MESSAGE_INIT;
  }

  otIp6AddressFromString(DALIPLUS_COAP_BROADCAST_ADDRESS,
                         &coapMessageInfo.mPeerAddr);
  coapMessageInfo.mPeerPort = DALIPLUS_COAP_PORT;

  otCoapMessageInit(coapMessage,
                    OT_COAP_TYPE_NON_CONFIRMABLE,
                    OT_COAP_CODE_POST);

  CHECK_THREAD_ERROR(otCoapMessageAppendUriPathOptions(coapMessage,
                                                       DALIPLUS_COAP_URI),
                     DALIPLUS_ERROR_MESSAGE_URI);

  CHECK_THREAD_ERROR(otCoapMessageSetPayloadMarker(coapMessage),
                     DALIPLUS_ERROR_MESSAGE_PAYLOAD_MARKER);

  daliplus_build_packet(isEncrypted,
                        messageInfo,
                        daliplusBuffer);

  CHECK_THREAD_ERROR(otMessageAppend(coapMessage, daliplusBuffer, totalLength),
                     DALIPLUS_ERROR_MESSAGE_APPEND);

  if (!can_send_forward_frame()) {
    return DALIPLUS_ERROR_MAX_FRAMES;
  }

  CHECK_THREAD_ERROR(otCoapSendRequest(daliplusInstance,
                                       coapMessage,
                                       &coapMessageInfo,
                                       daliplus_response_cb,
                                       daliplusInstance),
                     DALIPLUS_ERROR_MESSAGE_SEND);
  increment_ndu_sequence(isEncrypted);
  return DALIPLUS_ERROR_NONE;
}

/*******************************************************************************
 * @brief
 *  Response the forward message by sending various types of backward message
 ******************************************************************************/
daliplus_error_t daliplus_backward_response(bool isEncrypted,
                                            otMessage *requestMessage,
                                            const otMessageInfo *requestMessageInfo,
                                            daliplus_message_t *messageInfo)
{
  // Packet content (ADU/CDU/DDU) + 8 NDU bytes
  uint16_t totalLength = messageInfo->packetLength + DALIPLUS_NDU_FIELD_LENGTH;
  if (messageInfo->packetType == DALIPLUS_PACKET_ACK_ERROR) {
    totalLength -= 2;
  }

  // Plus another 18 bytes from the SDU field
  // minus 1 bytes from NDU field (omitted KeyID)
  if (isEncrypted) {
    totalLength += DALIPLUS_ENCRYPTED_FIELD_LENGTH;
  }

  uint8_t daliplusBackwardFrame[totalLength];
  memset(daliplusBackwardFrame, 0, sizeof(daliplusBackwardFrame));

  uint32_t jitterDelay = rand() % (udpMulticastResponseJitter);
  sl_sleeptimer_delay_millisecond(jitterDelay);

  otMessage *coapMessage = otCoapNewMessage(daliplusInstance, NULL);
  if (coapMessage == NULL) {
    return DALIPLUS_ERROR_MESSAGE_INIT;
  }

  otCoapType coapType;
  otCoapCode coapCode;

  switch (messageInfo->packetType)
  {
    case DALIPLUS_PACKET_ACK_ERROR:
      coapType = OT_COAP_TYPE_ACKNOWLEDGMENT;
      coapCode = OT_COAP_CODE_CHANGED;
      break;

    case DALIPLUS_PACKET_BACKWARD:
      if (messageInfo->packetLength > DALIPLUS_MAX_FRAME_LENGTH) {
        return DALIPLUS_ERROR_PACKET_OVERSIZED;
      }
      coapType = OT_COAP_TYPE_NON_CONFIRMABLE;
      coapCode = OT_COAP_CODE_CONTENT;
      break;

    case DALIPLUS_PACKET_ACK:
      coapType = OT_COAP_TYPE_ACKNOWLEDGMENT;
      coapCode = OT_COAP_CODE_VALID;
      break;

    default:
      return DALIPLUS_ERROR_PACKET_TYPE;
  }

  CHECK_THREAD_ERROR(otCoapMessageInitResponse(coapMessage,
                                               requestMessage,
                                               coapType,
                                               coapCode),
                     DALIPLUS_ERROR_MESSAGE_INIT);

  if (messageInfo->packetType != DALIPLUS_PACKET_ACK) {
    CHECK_THREAD_ERROR(otCoapMessageSetPayloadMarker(coapMessage),
                       DALIPLUS_ERROR_MESSAGE_PAYLOAD_MARKER);

    daliplus_build_packet(isEncrypted, messageInfo, daliplusBackwardFrame);

    CHECK_THREAD_ERROR(otMessageAppend(coapMessage,
                                       daliplusBackwardFrame,
                                       totalLength),
                       DALIPLUS_ERROR_MESSAGE_APPEND);
  }

  CHECK_THREAD_ERROR(otCoapSendResponse(daliplusInstance,
                                        coapMessage,
                                        requestMessageInfo),
                     DALIPLUS_ERROR_MESSAGE_SEND);
  if (messageInfo->packetType != DALIPLUS_PACKET_ACK) {
    increment_ndu_sequence(isEncrypted);
  }
  return DALIPLUS_ERROR_NONE;
}

/*******************************************************************************
 * @brief
 *  Decrypt the message.
 ******************************************************************************/
daliplus_error_t daliplus_decrypt_message(uint8_t const *const key,
                                          uint8_t *inputEncryptedMessage,
                                          uint16_t inputMessageSize,
                                          uint8_t *outputDecryptedMessage,
                                          uint16_t *outputMessageSize)
{
  // If the size of the message is too short, below CBC and NONCE length,
  // discard the operation
  if (inputMessageSize < (DALIPLUS_NONCE_LENGTH + DALIPLUS_CBCMAC_LENGTH)) {
    return DALIPLUS_ERROR_PACKET_UNDERSIZED;
  }

  uint16_t messageSize = inputMessageSize;
  uint16_t daliplusPayloadLength = messageSize
                                   - DALIPLUS_NONCE_LENGTH
                                   - DALIPLUS_CBCMAC_LENGTH;
  uint8_t daliplusBuffer[messageSize];
  memset(daliplusBuffer, 0, sizeof(daliplusBuffer));
  uint8_t daliplusNonce[DALIPLUS_NONCE_LENGTH] = { 0 };
  uint8_t daliplusCBCMAC[DALIPLUS_CBCMAC_LENGTH] = { 0 };
  uint8_t daliplusCiphertext[daliplusPayloadLength];
  memset(daliplusCiphertext, 0, sizeof(daliplusCiphertext));
  uint8_t daliplusDecryptedBuffer[daliplusPayloadLength];
  memset(daliplusDecryptedBuffer, 0, sizeof(daliplusDecryptedBuffer));

  mbedtls_ccm_free(&encryptCtx);

  memcpy(daliplusBuffer, inputEncryptedMessage, inputMessageSize);

  // First 10 bytes are NONCE
  memcpy(daliplusNonce, daliplusBuffer, DALIPLUS_NONCE_LENGTH);

  // Next 8 bytes are CBC-MAC
  memcpy(daliplusCBCMAC,
         &daliplusBuffer[DALIPLUS_NONCE_LENGTH],
         DALIPLUS_CBCMAC_LENGTH);

  // The rest of the bytes are encrypted payload
  memcpy(daliplusCiphertext,
         &daliplusBuffer[DALIPLUS_NONCE_LENGTH + DALIPLUS_CBCMAC_LENGTH],
         messageSize - DALIPLUS_NONCE_LENGTH - DALIPLUS_CBCMAC_LENGTH);

  if (key == NULL) {
    return DALIPLUS_ERROR_MESSAGE_DECRYPTION;
  }

  mbedtls_ccm_setkey(&encryptCtx,
                     MBEDTLS_CIPHER_ID_AES,
                     key,
                     DALIPLUS_BIND_KEY_LENGTH * 8);

  mbedtls_ccm_auth_decrypt(&encryptCtx, daliplusPayloadLength,
                           daliplusNonce, DALIPLUS_NONCE_LENGTH,
                           NULL, 0,
                           daliplusCiphertext, daliplusDecryptedBuffer,
                           daliplusCBCMAC, DALIPLUS_CBCMAC_LENGTH);

  *outputMessageSize = daliplusPayloadLength;
  memcpy(outputDecryptedMessage,
         daliplusDecryptedBuffer,
         daliplusPayloadLength);

  return DALIPLUS_ERROR_NONE;
}

/*******************************************************************************
 * @brief
 *  Update the NDU Sequence for every device to match, call this after every
 *  successfully received message (Get the NDU value from the message).
 ******************************************************************************/
void update_ndu_sequence(uint16_t value)
{
  udpNduSequenceNumber = value;
}

/*******************************************************************************
 * @brief
 *  Set non-volatile memory related variable.
 ******************************************************************************/
daliplus_error_t daliplus_set_nvm_var(uint8_t slot, void *value, uint16_t len)
{
  // Validate slot range
  if ((slot > NVM3_UDP_FRAME_COUNTER_SLOT)
      && (slot < NVM3_UDP_ENCRYPTION_KEY_SLOT)) {
    return DALIPLUS_ERROR_NVM3;
  }
  // Write to NVM3 storage
  nvm3_writeData(NVM3_DEFAULT_HANDLE, slot, value, len);
  // Define an array of pointers to corresponding variables
  void *targetVars[] = {
    [NVM3_UDP_ENCRYPTION_KEY_SLOT] = udpEncryptionKey,
    [NVM3_UDP_ACCESS_PERMISSION_SLOT] = udpAccessPermission,
    [NVM3_UDP_SENDER_ENCRYPTION_KEY_SLOT] = &udpSenderEncryptionKey,
    [NVM3_UDP_MULTICAST_SCOPE_SLOT] = &udpMulticastScope,
    [NVM3_UDP_MULTICAST_JITTER_SLOT] = &udpMulticastResponseJitter,
    [NVM3_UDP_104_SUBNET_SLOT] = &udp104Subnet,
    [NVM3_UDP_SENDER_ID_SLOT] = &udpSenderID,
    [NVM3_UDP_FRAME_COUNTER_SLOT] = &udpFrameCounter
  };
  // Perform memory copy if the slot is valid
  if ((slot < (sizeof(targetVars) / sizeof(targetVars[0])))
      && (targetVars[slot] != NULL)) {
    memcpy(targetVars[slot], value, len);
  }
  return DALIPLUS_ERROR_NONE;
}

/*******************************************************************************
 * @brief
 *  Read non-volatile memory related variable
 ******************************************************************************/
daliplus_error_t daliplus_read_nvm_var(uint8_t slot, void *value, uint16_t len)
{
  if ((slot > NVM3_UDP_FRAME_COUNTER_SLOT)
      && (slot < NVM3_UDP_ENCRYPTION_KEY_SLOT)) {
    return DALIPLUS_ERROR_NVM3;
  }

  nvm3_readData(NVM3_DEFAULT_HANDLE, slot, value, len);

  return DALIPLUS_ERROR_NONE;
}

/*******************************************************************************
 * @brief
 *  Log the received message (to be replaced later).
 ******************************************************************************/
SL_WEAK void daliplus_display_received_message(daliplus_packet_t packetType,
                                               uint8_t *packetPayload,
                                               uint16_t payloadLength)
{
  OT_UNUSED_VARIABLE(packetType);
  OT_UNUSED_VARIABLE(packetPayload);
  OT_UNUSED_VARIABLE(payloadLength);
}

/*******************************************************************************
 * @brief
 *  Callback whenever a CoAP request with a given Uri-Path is received
 *  (to be replaced later)
 ******************************************************************************/
SL_WEAK void daliplus_request_cb(void *aContext,
                                 otMessage *aMessage,
                                 const otMessageInfo *aMessageInfo)
{
  OT_UNUSED_VARIABLE(aContext);
  OT_UNUSED_VARIABLE(aMessage);
  OT_UNUSED_VARIABLE(aMessageInfo);
}

/*******************************************************************************
 * @brief
 *  Callback whenever a CoAP request with a given Uri-Path is received
 *  (to be replaced later)
 ******************************************************************************/
SL_WEAK void daliplus_response_cb(void *aContext,
                                  otMessage *aMessage,
                                  const otMessageInfo *aMessageInfo,
                                  otError aResult)
{
  OT_UNUSED_VARIABLE(aContext);
  OT_UNUSED_VARIABLE(aMessage);
  OT_UNUSED_VARIABLE(aMessageInfo);
  OT_UNUSED_VARIABLE(aResult);
}

/*******************************************************************************
 * @brief
 * Pointer is called during an IEEE 802.15.4 Active Scan when an IEEE 802.15.4
 * Beacon is received or the scan completes.
 ******************************************************************************/
SL_WEAK void daliplus_scan_cb(otActiveScanResult *aResult, void *aContext)
{
  OT_UNUSED_VARIABLE(aResult);
  OT_UNUSED_VARIABLE(aContext);
}

/*******************************************************************************
 * @brief
 *  Callback whenever there is a change in state (to be replaced later).
 ******************************************************************************/
SL_WEAK void netif_state_changed_cb(otChangedFlags aFlags, void *aContext)
{
  OT_UNUSED_VARIABLE(aFlags);
  OT_UNUSED_VARIABLE(aContext);
}

/*******************************************************************************
 * @brief
 *  Check whether it is fine to send a forward frame.
 ******************************************************************************/
static bool can_send_forward_frame(void)
{
  static uint32_t now = 0;
  now = sl_sleeptimer_get_tick_count();
  if (now - daliplusLastResetTime > sl_sleeptimer_ms_to_tick(10000)) {
    daliplusLastResetTime = now;
    daliplusSentFrames = 0;
  }
  return (daliplusSentFrames < MAX_FRAME_PER_TEN_SECONDS);
}

/*******************************************************************************
 * @brief
 *  Setup the Thread network
 ******************************************************************************/
static void setup_thread_network(void)
{
  otIp6Address multicastAddr;
  // Get address from string
  otIp6AddressFromString("ff03::1:1234", &multicastAddr);

  // Setup related Thread parameters
  thread_network_set_parameters();

  // Enable IPv6 interface
  otIp6SetEnabled(daliplusInstance, true);

  // Subscribe to the multicast address
  otIp6SubscribeMulticastAddress(daliplusInstance, &multicastAddr);

  // Enable the Thread network
  otThreadSetEnabled(daliplusInstance, true);

  // Determine this device is router eligible
  otThreadSetRouterEligible(daliplusInstance, true);

  // The higher the weight, the more likely to be voted to become
  // the leader in the Thread network
  otThreadSetLocalLeaderWeight(daliplusInstance, 255);

  // Become the Leader
  otThreadBecomeLeader(daliplusInstance);
}

/*******************************************************************************
 * @brief
 *  Setup the main DaliPlus device.
 ******************************************************************************/
static void daliplus_main_device_setup(void)
{
  char octet[2] = { 0 };
  uint8_t key[] = DALIPLUS_BIND_KEY_CONTENT;
  for (uint16_t i = 0; i < DALIPLUS_BIND_KEY_LENGTH; i++) {
    memcpy(octet, (uint8_t *)&key[2 * i], 2);
    udpEncryptionKey[i] = (uint8_t)strtol(octet, NULL, 16);
  }
  mbedtls_ccm_init(&encryptCtx);
  mbedtls_ccm_setkey(&encryptCtx,
                     MBEDTLS_CIPHER_ID_AES,
                     udpEncryptionKey,
                     DALIPLUS_BIND_KEY_LENGTH * 8);

  udpSenderID = 0x2468;
  udpSenderEncryptionKey = 0x01;
  for (uint8_t i = 0; i < 8; i++) {
    udpAccessPermission[i] = 1;
  }
  daliplus_set_nvm_var(NVM3_UDP_ENCRYPTION_KEY_SLOT,
                       udpEncryptionKey,
                       DALIPLUS_BIND_KEY_LENGTH);
  daliplus_set_nvm_var(NVM3_UDP_SENDER_ID_SLOT,
                       &udpSenderID,
                       sizeof(udpSenderID));
  daliplus_set_nvm_var(NVM3_UDP_SENDER_ENCRYPTION_KEY_SLOT,
                       &udpSenderEncryptionKey,
                       sizeof(udpSenderEncryptionKey));
  daliplus_set_nvm_var(NVM3_UDP_ACCESS_PERMISSION_SLOT,
                       udpAccessPermission,
                       sizeof(udpAccessPermission));
}

/*******************************************************************************
 * @brief
 *  Set Thread network parameters.
 ******************************************************************************/
static void thread_network_set_parameters(void)
{
  otOperationalDataset sDataset;
  memset(&sDataset, 0, sizeof(otOperationalDataset));

  // The active timestamp is a value that indicates when the dataset
  // became active
  sDataset.mActiveTimestamp.mSeconds = 1;
  sDataset.mActiveTimestamp.mTicks = 0;
  sDataset.mActiveTimestamp.mAuthoritative = true;
  sDataset.mComponents.mIsActiveTimestampPresent = true;

  // In IEEE 802.15.4, at 2.4Ghz band, channel 11 to 26 are available
  // for Thread.
  // This tells that the network is talking on channel 19 right now,
  // it may be changed later if interference happens.
  sDataset.mChannel = DALIPLUS_THREAD_NETWORK_CHANNEL;
  sDataset.mComponents.mIsChannelPresent = true;

  // This tells that channel 11 to channel 26 is valid in case of
  // interference happening and the network needs to change its channel.
  sDataset.mChannelMask = (otChannelMask)0x7FFF800;
  sDataset.mComponents.mIsChannelMaskPresent = true;

  // PAN ID is used to uniquely indentify a Thread network, basically
  // differentiate one network from another.
  sDataset.mPanId = (otPanId)DALIPLUS_THREAD_PANID;
  sDataset.mComponents.mIsPanIdPresent = true;

  // Extended PAN ID is used to avoid collision with those with the same
  // PAN ID
  uint8_t extended_pan_id[OT_EXT_PAN_ID_SIZE] = DALIPLUS_THREAD_EXTENDED_PANID;
  memcpy(sDataset.mExtendedPanId.m8, extended_pan_id, sizeof(extended_pan_id));
  sDataset.mComponents.mIsExtendedPanIdPresent = true;

  // Network key is used for authentication and security.
  // Use default value from openThread
  uint8_t masterKey[OT_NETWORK_KEY_SIZE] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };
  memcpy(sDataset.mNetworkKey.m8, masterKey, sizeof(masterKey));
  sDataset.mComponents.mIsNetworkKeyPresent = true;

  // Network name is for administrator to easily track, should be
  // less than OT_NETWORK_NAME_MAX_SIZE
  if (strlen(DALIPLUS_THREAD_NETWORK_NAME) < OT_NETWORK_NAME_MAX_SIZE) {
    memcpy(sDataset.mNetworkName.m8,
           DALIPLUS_THREAD_NETWORK_NAME,
           strlen(DALIPLUS_THREAD_NETWORK_NAME));
  } else {
    memcpy(sDataset.mNetworkName.m8,
           DALIPLUS_THREAD_NETWORK_NAME,
           OT_NETWORK_NAME_MAX_SIZE - 1);
  }
  sDataset.mComponents.mIsNetworkNamePresent = true;

  // Mesh local address of the device in the Thread network
  uint8_t meshLocalPrefix[OT_MESH_LOCAL_PREFIX_SIZE] = {
    0xfd, 0x00, 0x00, 0x00, 0xfb, 0x01, 0x00, 0x01
  };
  memcpy(sDataset.mMeshLocalPrefix.m8,
         meshLocalPrefix,
         sizeof(sDataset.mMeshLocalPrefix));
  sDataset.mComponents.mIsMeshLocalPrefixPresent = true;

  uint8_t PSKc[OT_PSKC_MAX_SIZE] =
  { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x00 };
  memcpy(&sDataset.mPskc, PSKc, sizeof(sDataset.mPskc));
  sDataset.mComponents.mIsPskcPresent = true;

  sDataset.mSecurityPolicy.mNativeCommissioningEnabled = true;
  sDataset.mComponents.mIsSecurityPolicyPresent = true;

  otDatasetSetActive(daliplusInstance, &sDataset);
}

/*******************************************************************************
 * @brief
 *  Initialize CoAP server.
 ******************************************************************************/
static void coap_init(void)
{
  otCoapStart(daliplusInstance, DALIPLUS_COAP_PORT);
  otCoapAddResource(daliplusInstance, &daliplusCoapResource);
}

/*******************************************************************************
 * @brief
 *  Initialize all NVM variable.
 ******************************************************************************/
static void daliplus_persistent_var_init(void)
{
  uint16_t numberOfObjects = 0;
  if (nvm3_initDefault() != ECODE_NVM3_OK) {
    return;
  }

  numberOfObjects = nvm3_countObjects(NVM3_DEFAULT_HANDLE);

  struct {
    uint16_t slot;
    void *data;
    uint16_t size;
  } nvm3Data[] = {
    { NVM3_UDP_ENCRYPTION_KEY_SLOT, udpEncryptionKey,
      sizeof(udpEncryptionKey) },
    { NVM3_UDP_ACCESS_PERMISSION_SLOT, udpAccessPermission,
      sizeof(udpAccessPermission) },
    { NVM3_UDP_SENDER_ENCRYPTION_KEY_SLOT, &udpSenderEncryptionKey,
      sizeof(udpSenderEncryptionKey) },
    { NVM3_UDP_MULTICAST_SCOPE_SLOT, &udpMulticastScope,
      sizeof(udpMulticastScope) },
    { NVM3_UDP_MULTICAST_JITTER_SLOT, &udpMulticastResponseJitter,
      sizeof(udpMulticastResponseJitter) },
    { NVM3_UDP_104_SUBNET_SLOT, &udp104Subnet, sizeof(udp104Subnet) },
    { NVM3_UDP_SENDER_ID_SLOT, &udpSenderID, sizeof(udpSenderID) },
    { NVM3_UDP_FRAME_COUNTER_SLOT, &udpFrameCounter, sizeof(udpFrameCounter) }
  };

  // If there are no prior object, write initial data
  if (numberOfObjects == 0) {
    nvm3_eraseAll(NVM3_DEFAULT_HANDLE);
    for (uint16_t i = 0; i < sizeof(nvm3Data) / sizeof(nvm3Data[0]); ++i) {
      nvm3_writeData(NVM3_DEFAULT_HANDLE,
                     nvm3Data[i].slot,
                     nvm3Data[i].data,
                     nvm3Data[i].size);
    }
    return;
  }

  // If there are prior objects, fetch those values out
  for (uint16_t i = 0; i < sizeof(nvm3Data) / sizeof(nvm3Data[0]); ++i) {
    nvm3_readData(NVM3_DEFAULT_HANDLE,
                  nvm3Data[i].slot,
                  nvm3Data[i].data,
                  nvm3Data[i].size);
  }

  // Check if repack is needed
  if (nvm3_repackNeeded(NVM3_DEFAULT_HANDLE)) {
    nvm3_repack(NVM3_DEFAULT_HANDLE);
  }
}

static void increment_ndu_sequence(bool isEncrypted)
{
  // Reset the value
  if (udpNduSequenceNumber == 0xFF) {
    udpNduSequenceNumber = 0;
    return;
  }

  udpNduSequenceNumber++;
  daliplusSentFrames++;
  if (isEncrypted) {
    udpFrameCounter++;
    nvm3_writeData(NVM3_DEFAULT_HANDLE,
                   NVM3_UDP_FRAME_COUNTER_SLOT,
                   &udpFrameCounter,
                   sizeof(udpFrameCounter));
  }
}

/*******************************************************************************
 * @brief
 *  Forward a message to the desired address.
 ******************************************************************************/
static daliplus_error_t daliplus_build_packet(bool isEncrypted,
                                              daliplus_message_t *messageInfo,
                                              uint8_t *outputDataFrame)
{
  uint8_t bufferIndex = 0;
  uint8_t payloadIndex = 0;
  uint16_t dataLength = messageInfo->packetLength;
  uint16_t totalLength = dataLength + DALIPLUS_NDU_FIELD_LENGTH;

  // If encryption is enabled
  if (isEncrypted) {
    // Adjust total length for ACK_ERROR
    if (messageInfo->packetType == DALIPLUS_PACKET_ACK_ERROR) {
      totalLength -= 3;
    } else {
      totalLength -= 1;
    }
    uint8_t daliplusPayload[totalLength];
    memset(daliplusPayload, 0, sizeof(daliplusPayload));
    uint8_t daliplusNonce[10] = { 0 };
    uint8_t daliplusBuffer[18 + totalLength];
    memset(daliplusBuffer, 0, sizeof(daliplusBuffer));
    uint8_t ciphertext[totalLength];
    memset(ciphertext, 0, sizeof(ciphertext));
    uint8_t encryptionCBC[8] = { 0 };

    // Header fields
    daliplusNonce[0] = 0x01;    // Key ID but for SDU
    daliplusNonce[1] = (udp104Subnet >> 8);    // Sender ID high byte
    daliplusNonce[2] = ((uint8_t)udp104Subnet & 0xFF);    // Sender ID low byte
    daliplusNonce[3] = (udpSenderID >> 8);    // Subnet high byte
    daliplusNonce[4] = ((uint8_t)udpSenderID & 0xFF);    // Subnet low byte
    daliplusNonce[5] = (udpFrameCounter >> 32);    // Frame counter high byte
    daliplusNonce[6] = (udpFrameCounter >> 24);    // Frame counter mid-high byte
    daliplusNonce[7] = (udpFrameCounter >> 16);    // Frame counter mid byte
    daliplusNonce[8] = (udpFrameCounter >> 8);    // Frame counter mid-low byte
    daliplusNonce[9] = ((uint8_t)udpFrameCounter & 0xFF);    // Frame low counter

    // Actual payload fields
    daliplusPayload[payloadIndex++] = messageInfo->packetType      // NDU length
                                      | (messageInfo->packetType
                                         == DALIPLUS_PACKET_ACK_ERROR
                                         ?DALIPLUS_PACKET_NDU_LENGTH
                                         - 3 : DALIPLUS_PACKET_NDU_LENGTH - 1);
    daliplusPayload[payloadIndex++] = DALIPLUS_PACKET_NDU_VERSION;
    daliplusPayload[payloadIndex++] = (uint8_t)(udpNduSequenceNumber >> 8);
    daliplusPayload[payloadIndex++] = (uint8_t)udpNduSequenceNumber;
    if (messageInfo->packetType != DALIPLUS_PACKET_DISCOVERY) {
      daliplusPayload[payloadIndex++] = DALIPLUS_PACKET_NDU_SYSTEM_ADDR;
    } else {
      daliplusPayload[payloadIndex++] = 0x00;       // Discovery uses 0x00 instead
    }

    if (messageInfo->packetType != DALIPLUS_PACKET_ACK_ERROR) {
      daliplusPayload[payloadIndex++] = (uint8_t)((dataLength >> 8) & 0x03);
      daliplusPayload[payloadIndex++] = (uint8_t)(dataLength & 0xFF);
    }

    // Copy message content
    memcpy(&daliplusPayload[payloadIndex],
           messageInfo->packetContent,
           dataLength);
    payloadIndex += dataLength;

    if (mbedtls_ccm_encrypt_and_tag(&encryptCtx, payloadIndex,
                                    daliplusNonce, sizeof(daliplusNonce),
                                    NULL, 0,
                                    daliplusPayload, ciphertext,
                                    encryptionCBC,
                                    sizeof(encryptionCBC)) != 0) {
      return DALIPLUS_ERROR_MESSAGE_ENCRYPTION;
    }

    memcpy(daliplusBuffer, daliplusNonce, sizeof(daliplusNonce));
    memcpy(&daliplusBuffer[10], encryptionCBC, sizeof(encryptionCBC));
    memcpy(&daliplusBuffer[18], ciphertext, totalLength);

    /* Copy final data frame */
    memcpy(outputDataFrame, daliplusBuffer, totalLength + 18);
    return DALIPLUS_ERROR_NONE;
  }
  // Adjust total length for ACK_ERROR
  if (messageInfo->packetType == DALIPLUS_PACKET_ACK_ERROR) {
    totalLength -= 2;
  }
  uint8_t daliplusBuffer[18 + totalLength];
  memset(daliplusBuffer, 0, sizeof(daliplusBuffer));
  daliplusBuffer[bufferIndex++] = DALIPLUS_PACKET_NONENCRYPTED;
  daliplusBuffer[bufferIndex++] = messageInfo->packetType
                                  | (messageInfo->packetType
                                     == DALIPLUS_PACKET_ACK_ERROR
                                     ?DALIPLUS_PACKET_NDU_LENGTH
                                     - 2 : DALIPLUS_PACKET_NDU_LENGTH);
  daliplusBuffer[bufferIndex++] = DALIPLUS_PACKET_NDU_VERSION;
  daliplusBuffer[bufferIndex++] = (uint8_t)(udpNduSequenceNumber >> 8);
  daliplusBuffer[bufferIndex++] = (uint8_t)udpNduSequenceNumber;
  if (messageInfo->packetType != DALIPLUS_PACKET_DISCOVERY) {
    daliplusBuffer[bufferIndex++] = DALIPLUS_PACKET_NDU_SYSTEM_ADDR;
  } else {
    daliplusBuffer[bufferIndex++] = 0x00;     // Discovery packet uses 0x00 instead
  }
  // Data length
  if (messageInfo->packetType != DALIPLUS_PACKET_ACK_ERROR) {
    daliplusBuffer[bufferIndex++] = (uint8_t)((dataLength >> 8) & 0x03);
    daliplusBuffer[bufferIndex++] = (uint8_t)(dataLength & 0xFF);
  }

  // Copy message content
  memcpy(&daliplusBuffer[bufferIndex], messageInfo->packetContent, dataLength);
  // Copy final data frame
  memcpy(outputDataFrame, daliplusBuffer, totalLength);
  return DALIPLUS_ERROR_NONE;
}
