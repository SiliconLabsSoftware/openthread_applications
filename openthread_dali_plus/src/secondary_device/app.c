/*******************************************************************************
 * @file app.c
 * @brief Core application logic.
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
#include <openthread/config.h>
#include <openthread/diag.h>
#include <openthread/tasklet.h>

#include "app_log.h"
#include "inc/daliplus.h"
#include "openthread-system.h"
#include "openthread-core-config.h"
#include "sl_simple_button_instances.h"

#define UPDATE_MESSAGE_INFO(Type, Content, Length) \
  bwd_msg_info.packetType = Type;                  \
  bwd_msg_info.packetContent = Content;            \
  bwd_msg_info.packetLength = Length

static uint8_t current_bind_key[DALIPLUS_BIND_KEY_LENGTH] = { 0 };
static uint8_t daliplus_res_scencario = 0;
static bool found_network = false;
static bool check_scenario = false;

// Random data frame for demonstration, not real DALI+ command
static uint8_t bwd_frame = 0x64;

// Just random error frame, feel free to change it
static uint8_t bwd_ack_error[2] = { 0x12, 0x34 };

static daliplus_message_t bwd_msg_info = { DALIPLUS_PACKET_BACKWARD,
                                           &bwd_frame,
                                           sizeof(bwd_frame) };

void otPlatLog(otLogLevel aLogLevel,
               otLogRegion aLogRegion,
               const char *aFormat,
               ...)
{
  OT_UNUSED_VARIABLE(aLogLevel);
  OT_UNUSED_VARIABLE(aLogRegion);
  OT_UNUSED_VARIABLE(aFormat);
}

/******************************************************************************
 * Application Init.
 *****************************************************************************/
void app_init(void)
{
  app_log("------DALI+ Secondary Device using Thread example!------\r\n");

  // Register callback whenever a state change happens
  app_log("Secondary device: Set state changed callback 0x%02X!\r\n",
          otSetStateChangedCallback(get_daliplus_instance(),
                                    netif_state_changed_cb,
                                    get_daliplus_instance()));
  // Enable IPv6 interface
  app_log("Secondary device: Set Ip6 interface 0x%02X!\r\n",
          otIp6SetEnabled(get_daliplus_instance(), true));

  // Start discovering Thread network
  app_log(
    "Secondary device: Discovering nearby DALI+ Thread network 0x%02X!\r\n",
    otThreadDiscover(get_daliplus_instance(),
                     DALIPLUS_COAP_ALL_ELIGIBLE_CHANNEL_MASK,
                     OT_PANID_BROADCAST, false, false, daliplus_scan_cb,
                     get_daliplus_instance()));
}

/******************************************************************************
 * Application Process Action.
 *****************************************************************************/
void app_process_action(void)
{
  otTaskletsProcess(get_daliplus_instance());
  otSysProcessDrivers(get_daliplus_instance());
  if (check_scenario) {
    app_log("Secondary device: %s response scenario\r\n",
            (daliplus_res_scencario == DALIPLUS_RESPONSE_COAP_ACK) ? "Simple CoAP ACK"
            : ((daliplus_res_scencario == DALIPLUS_RESPONSE_EXECUTED_NO_REPLY)
               ?
               "Executed but no reply(Simple UDP ACK packet with error indicator)"
               : "Executed with reply (Backward packet)"));
    daliplus_res_scencario++;
    if (daliplus_res_scencario > DALIPLUS_RESPONSE_EXECUTED_NO_REPLY) {
      daliplus_res_scencario = 0;
    }
    check_scenario = false;
  }
}

void daliplus_scan_cb(otActiveScanResult *aResult, void *aContext)
{
  OT_UNUSED_VARIABLE(aContext);
  uint8_t cmpPanID[OT_EXT_PAN_ID_SIZE] = DALIPLUS_THREAD_EXTENDED_PANID;

  // If the correct network has been found
  if ((aResult != NULL)
      && (!strcmp(aResult->mNetworkName.m8, DALIPLUS_THREAD_NETWORK_NAME))
      && (aResult->mPanId == DALIPLUS_THREAD_PANID)
      && (!memcmp(aResult->mExtendedPanId.m8, cmpPanID, OT_EXT_PAN_ID_SIZE))) {
    app_log("Secondary device: Found the correct Thread network:\r\n");
    app_log(" - Network name: %s\r\n", aResult->mNetworkName.m8);
    app_log(" - Channel: %d\r\n", aResult->mChannel);
    app_log(" - PAN ID: 0x%04X\r\n", aResult->mPanId);
    app_log(" - Extended PAN ID: 0x");
    for (size_t i = 0; i < OT_EXT_PAN_ID_SIZE; i++) {
      app_log("%02X", aResult->mExtendedPanId.m8[i]);
    }
    app_log("\r\n");
    daliplus_init(DALIPLUS_ROLE_SECONDARY_DEVICE);   // Begin initialization here
    app_log("Secondary device: Done initializing!\r\n");
    found_network = true;
  }

  if (aResult == NULL) {
    if (found_network) {
      // Start joiner process if the correct network had been found and the
      // scanning session ended
      app_log(
        "Secondary device: Done scanning, begins joining process 0x%02X!\r\n",
        otJoinerStart(get_daliplus_instance(),
                      DALIPLUS_INPUT_DEVICE_PSK, NULL, PACKAGE_NAME,
                      OPENTHREAD_CONFIG_PLATFORM_INFO, PACKAGE_VERSION,
                      NULL, NULL, get_daliplus_instance()));
      return;
    }
    app_log("Secondary device: Failed to find the correct network,"
            " retrying scan process 0x%02X\r\n",
            otThreadDiscover(get_daliplus_instance(),
                             DALIPLUS_COAP_ALL_ELIGIBLE_CHANNEL_MASK,
                             OT_PANID_BROADCAST, false, false, daliplus_scan_cb,
                             get_daliplus_instance()));
  }
}

void netif_state_changed_cb(otChangedFlags aFlags, void *aContext)
{
  // If the change happens with Thread role
  if ((aFlags & OT_CHANGED_THREAD_ROLE)) {
    otDeviceRole changedRole = otThreadGetDeviceRole(aContext);

    switch (changedRole)
    {
      case OT_DEVICE_ROLE_LEADER:
        app_log("Secondary device: Has become leader\r\n");

        // Don't personally want the secondary device to become the
        // leader so factory reset here. This happens only when
        // the main device is absent.
        otInstanceFactoryReset(get_daliplus_instance());
        break;

      // Detached role is not wanted, wait around 1 or 2 minutes
      // for it to become other role to start communication
      case OT_DEVICE_ROLE_DETACHED:
        app_log("%s\r\n%s\r\n",
                "Secondary device: Has become detached",
                "Please wait until the device is reassigned to another role");
        break;

      case OT_DEVICE_ROLE_ROUTER:
        app_log("Secondary device: Has become router\r\n");
        break;

      case OT_DEVICE_ROLE_CHILD:
        app_log("%s\r\n%s\r\n",
                "Secondary device: Has become child",
                "Secondary device: Broadcasting presence!");

        // Send the EUI64 to the main device to process
        uint8_t discoveryData[OT_EXT_ADDRESS_SIZE + OT_IP6_ADDRESS_SIZE
                              + 1] = { 0 };
        otExtAddress EUI64Addr;
        discoveryData[0] = 0x00;
        otLinkGetFactoryAssignedIeeeEui64(get_daliplus_instance(), &EUI64Addr);
        memcpy(&discoveryData[1], EUI64Addr.m8, OT_EXT_ADDRESS_SIZE);
        daliplus_message_t discoveryMessageInfo = {
          DALIPLUS_PACKET_DISCOVERY,
          discoveryData,
          OT_EXT_ADDRESS_SIZE + OT_IP6_ADDRESS_SIZE + 1
        };

        // Broadcast the UDP discovery packet
        if (daliplus_broadcast_coap_message(false,
                                            &discoveryMessageInfo)
            != DALIPLUS_ERROR_NONE) {
          app_log("Secondary device: Failed to broadcast presence !\r\n");
          return;
        }
        app_log("Secondary device: Presence broadcasted!\r\n");
        break;

      default:
        break;
    }
  }
  if (aFlags & OT_CHANGED_JOINER_STATE) {
    app_log("Secondary device (Joining process): %s\r\n",
            otJoinerStateToString(otJoinerGetState(get_daliplus_instance())));
    otJoinerState changedState = otJoinerGetState(get_daliplus_instance());

    // At the end of the joining process (entrust), Thread shall be enabled
    if (changedState == OT_JOINER_STATE_JOINED) {
      app_log("Secondary device: Joined DALI+ Thread network 0x%02X!\r\n",
              otThreadSetEnabled(get_daliplus_instance(), true));
    }
  }
}

void daliplus_request_cb(void *aContext,
                         otMessage *aMessage,
                         const otMessageInfo *aMessageInfo)
{
  OT_UNUSED_VARIABLE(aContext);
  uint8_t daliplus_payload[128] = { 0 };
  uint16_t daliplus_len = otMessageRead(aMessage,
                                        otMessageGetOffset(aMessage),
                                        daliplus_payload,
                                        sizeof(daliplus_payload));

  otCoapCode msg_code = otCoapMessageGetCode(aMessage);
  otCoapType msg_type = otCoapMessageGetType(aMessage);

  if ((msg_type != OT_COAP_TYPE_CONFIRMABLE)
      || (msg_code != OT_COAP_CODE_POST)) {
    app_log("Secondary device: Error message type or code\r\n");
    return;
  }

  // If the keyID is not 0xDA, this means encrypted data
  if (daliplus_payload[0] != DALIPLUS_PACKET_NONENCRYPTED) {
    uint8_t decrypted_payload[128] = { 0 };
    uint16_t decrypted_payload_len = 0;

    // Display the encrypted message first to see
    daliplus_display_received_message(DALIPLUS_PACKET_ENCRYPTED,
                                      daliplus_payload,
                                      daliplus_len);
    app_log("Secondary device: Decrypting message 0x%02X\r\n",
            daliplus_decrypt_message(current_bind_key, daliplus_payload,
                                     daliplus_len, decrypted_payload,
                                     &decrypted_payload_len));

    // Display the decrypted message
    app_log("Secondary device: Decrypted message 0x");
    for (uint16_t i = 0; i < decrypted_payload_len; i++) {
      app_log("%02X", decrypted_payload[i]);
    }
    app_log("\r\n");

    // Update the NDU sequence to synchronize the both device
    update_ndu_sequence((decrypted_payload[2] << 8)
                        | (decrypted_payload[3] & 0xFF));

    // Response back to the main device to confirm the message
    // has been delivered
    app_log("Secondary device: Responding back to main device 0x%02X\r\n",
            daliplus_backward_response(true, aMessage, aMessageInfo,
                                       &bwd_msg_info));
    return;
  }

  // If this is the UDP configuration packet
  if ((daliplus_payload[1] & 0x20)) {
    // Extract all the configuration values
    uint16_t conf_subnet = (((uint16_t)daliplus_payload[10] << 8)
                            | daliplus_payload[11]);
    uint16_t conf_sender_id = (((uint16_t)daliplus_payload[12] << 8)
                               | daliplus_payload[13]);
    uint8_t conf_scope = daliplus_payload[14];
    uint8_t conf_sender_key = daliplus_payload[15];
    uint8_t conf_access_per = daliplus_payload[17];

    // Store values in NVM3.
    daliplus_set_nvm_var(NVM3_UDP_104_SUBNET_SLOT,
                         &conf_subnet, sizeof(conf_subnet));
    daliplus_set_nvm_var(NVM3_UDP_SENDER_ID_SLOT,
                         &conf_sender_id, sizeof(conf_sender_id));
    daliplus_set_nvm_var(NVM3_UDP_MULTICAST_SCOPE_SLOT,
                         &conf_scope, sizeof(conf_scope));
    daliplus_set_nvm_var(NVM3_UDP_SENDER_ENCRYPTION_KEY_SLOT,
                         &conf_sender_key, sizeof(conf_sender_key));
    daliplus_set_nvm_var(NVM3_UDP_ACCESS_PERMISSION_SLOT,
                         &conf_access_per, sizeof(conf_access_per));

    // Update bind key and store it into NVM3
    memcpy(current_bind_key, &daliplus_payload[18], DALIPLUS_BIND_KEY_LENGTH);
    daliplus_set_nvm_var(NVM3_UDP_ENCRYPTION_KEY_SLOT,
                         current_bind_key, sizeof(current_bind_key));

    daliplus_message_t bwdAck = {
      DALIPLUS_PACKET_ACK,
      NULL,
      0
    };

    app_log("Secondary device: Got bind key ");
    for (uint16_t i = 0; i < DALIPLUS_BIND_KEY_LENGTH; i++) {
      app_log("%02X", current_bind_key[i]);
    }

    // Send confirmation that the packet has been delivered
    app_log("\r\nSecondary device: Responding back to main device 0x%02X\r\n",
            daliplus_backward_response(true, aMessage, aMessageInfo,
                                       &bwdAck));

    app_log("Secondary device: Press button 0 to change response scenario\r\n");
    return;
  }

  // Update the NDU sequence to synchronize the both device
  update_ndu_sequence((daliplus_payload[3] << 8)
                      | (daliplus_payload[4] & 0xFF));

  // Display the forward packet from the main device
  daliplus_display_received_message(DALIPLUS_PACKET_FORWARD,
                                    daliplus_payload,
                                    daliplus_len);

  // Response back to the main device
  app_log("Secondary device: Responding back to main device 0x%02X\r\n",
          daliplus_backward_response(true, aMessage, aMessageInfo,
                                     &bwd_msg_info));
}

void daliplus_display_received_message(daliplus_packet_t packetType,
                                       uint8_t *packetPayload,
                                       uint16_t payloadLength)
{
  uint16_t daliplusIndex = 0;
  uint8_t daliplusBuffer[payloadLength];
  // Copy the packet payload into a local buffer
  memcpy(daliplusBuffer, packetPayload, payloadLength);
  // If the packet is an acknowledgment, log a success message and return
  if (packetType == DALIPLUS_PACKET_ACK) {
    app_log("Secondary device: Delivery confirmed!\r\n");
    return;
  }
  // Ensure that the packet is not too short to process
  if (payloadLength < 8) {
    app_log("Secondary device: CoAP message is too short (%d bytes)\n",
            payloadLength);
    return;
  }
  // Handle encrypted messages (Key ID != 0xDA)
  if ((packetPayload[0] != DALIPLUS_PACKET_NONENCRYPTED)
      && (packetType == DALIPLUS_PACKET_ENCRYPTED)) {
    app_log("Secondary device: Got encrypted CoAP message:\n");
    // Log packet metadata
    app_log("  - Key ID: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
    app_log("  - Sub-net: 0x%02X%02X\n", daliplusBuffer[daliplusIndex],
            daliplusBuffer[daliplusIndex + 1]);
    daliplusIndex += 2;
    app_log("  - Sender ID: 0x%02X%02X\n", daliplusBuffer[daliplusIndex],
            daliplusBuffer[daliplusIndex + 1]);
    daliplusIndex += 2;
    app_log("  - Frame Counter: 0x%02X%02X%02X%02X%02X\r\n",
            daliplusBuffer[daliplusIndex],
            daliplusBuffer[daliplusIndex + 1],
            daliplusBuffer[daliplusIndex + 2],
            daliplusBuffer[daliplusIndex + 3],
            daliplusBuffer[daliplusIndex + 4]);
    daliplusIndex += 5;
    // Log authentication field (8 bytes)
    app_log("  - Authentication field: 0x");
    for (uint8_t i = 0; i < 8; i++)
    {
      app_log("%02X", daliplusBuffer[daliplusIndex++]);
    }
    app_log("\r\n");
    // Log the encrypted message content
    app_log("  - Encrypted message:");
    for (uint16_t i = daliplusIndex; i < payloadLength; i++)
    {
      app_log("%02X", daliplusBuffer[daliplusIndex++]);
    }
    app_log("\r\n");
    return;
  }
  // Process different packet types
  switch (packetType)
  {
    case DALIPLUS_PACKET_FORWARD:
    case DALIPLUS_PACKET_BACKWARD:
      app_log("Secondary device: Got %s CoAP message:\n",
              (packetType == DALIPLUS_PACKET_FORWARD) ? "forward" : "backward");
      // Extract and log message metadata
      app_log("  - Key ID: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      app_log("  - NDU Length: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      app_log("  - NDU Flags: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      app_log("  - NDU Sequence: 0x%02X%02X\n", daliplusBuffer[daliplusIndex],
              daliplusBuffer[daliplusIndex + 1]);
      daliplusIndex += 2;
      app_log("  - System Address: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      // Extract ADU Length (last 2 bits of the first byte and full second byte)
      uint16_t aduLength = ((daliplusBuffer[daliplusIndex++] & 0x03) << 8);
      aduLength |= daliplusBuffer[daliplusIndex++];
      app_log("  - ADU Length: %d\n  - ADU Data: ", aduLength);
      // Log ADU data
      for (size_t i = 0; i < aduLength && daliplusIndex < payloadLength; i++)
      {
        app_log("%02X", daliplusBuffer[daliplusIndex++]);
      }
      app_log("\n");
      break;
    case DALIPLUS_PACKET_DISCOVERY:
    case DALIPLUS_PACKET_NETWORK_CONFIG:
      app_log("Secondary device: Got %s CoAP message:\n",
              (packetType
               == DALIPLUS_PACKET_DISCOVERY) ? "discovery" : "network configuration");
      // Extract and log message metadata
      app_log("  - Key ID: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      app_log("  - NDU Length: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      app_log("  - NDU Flags: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      app_log("  - NDU Sequence: 0x%02X%02X\n", daliplusBuffer[daliplusIndex],
              daliplusBuffer[daliplusIndex + 1]);
      daliplusIndex += 2;
      app_log("  - System Address: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      // Extract and log CDU/DDU Length
      uint16_t length = ((daliplusBuffer[daliplusIndex++] & 0x03) << 8);
      length |= daliplusBuffer[daliplusIndex++];
      app_log("  - %s Length: %d\n",
              (packetType == DALIPLUS_PACKET_DISCOVERY) ? "DDU" : "CDU",
              length);
      // Extract and log CDU/DDU Flags
      app_log("  - %s Flags: 0x%02X\n",
              (packetType == DALIPLUS_PACKET_DISCOVERY) ? "DDU" : "CDU",
              daliplusBuffer[daliplusIndex++]);
      // Log CDU/DDU Data
      app_log("  - %s Data: ",
              (packetType == DALIPLUS_PACKET_DISCOVERY) ? "DDU" : "CDU");
      for (size_t i = 0; i < length && daliplusIndex < payloadLength; i++)
      {
        app_log("%02X", daliplusBuffer[daliplusIndex++]);
      }
      app_log("\n");
      break;
    case DALIPLUS_PACKET_ACK_ERROR:
      app_log("Secondary device: Got ACK with error CoAP message with:\n");
      // Extract and log error message metadata
      app_log("  - Key ID: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      app_log("  - NDU Length: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      app_log("  - NDU Flags: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      app_log("  - NDU Sequence: 0x%02X%02X\n", daliplusBuffer[daliplusIndex],
              daliplusBuffer[daliplusIndex + 1]);
      daliplusIndex += 2;
      app_log("  - System Address: 0x%02X\n", daliplusBuffer[daliplusIndex++]);
      // Extract and log error indicator
      app_log("  - Error Indicator: 0x%02X%02X\n",
              daliplusBuffer[daliplusIndex], daliplusBuffer[daliplusIndex + 1]);
      daliplusIndex += 2;
      break;
    default:
      // Log an error if an invalid packet type is received
      app_log("Secondary device: Invalid DALI+ packet type!\r\n");
      break;
  }
}

void sl_button_on_change(const sl_button_t *handle)
{
  if ((sl_button_get_state(handle) == SL_SIMPLE_BUTTON_PRESSED)
      && (SL_SIMPLE_BUTTON_INSTANCE(0) == handle)) {
    check_scenario = true;
    switch (daliplus_res_scencario)
    {
      case DALIPLUS_RESPONSE_COAP_ACK:
        UPDATE_MESSAGE_INFO(DALIPLUS_PACKET_ACK, NULL, 0);
        break;

      case DALIPLUS_RESPONSE_EXECUTED_REPLY:
        UPDATE_MESSAGE_INFO(DALIPLUS_PACKET_BACKWARD,
                            &bwd_frame,
                            sizeof(bwd_frame));
        break;

      case DALIPLUS_RESPONSE_EXECUTED_NO_REPLY:
        UPDATE_MESSAGE_INFO(DALIPLUS_PACKET_ACK_ERROR, bwd_ack_error,
                            sizeof(bwd_ack_error));
        break;
    }
  }
}
