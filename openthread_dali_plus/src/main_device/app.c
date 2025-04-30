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
#include <openthread/tasklet.h>

#include "app_log.h"
#include "inc/daliplus.h"
#include "openthread-system.h"
#include "openthread-core-config.h"
#include "sl_simple_button_instances.h"

static daliplus_device_t device_list[10];
static uint16_t daliplus_device_index = 0;

// Demonstration data, not actual DALI command
static uint8_t fwd_frame[2] = { 0xFF, 0x40 };
static daliplus_message_t fwd_msg = { DALIPLUS_PACKET_FORWARD,
                                      fwd_frame,
                                      sizeof(fwd_frame) };
static bool send_flag = false;
static bool is_encrypted = false;
static bool check_encrypted = false;

// Do nothing here, basically just to avoid undefined error
void otPlatLog(otLogLevel aLogLevel,
               otLogRegion aLogRegion,
               const char *aFormat,
               ...)
{
  OT_UNUSED_VARIABLE(aLogLevel);
  OT_UNUSED_VARIABLE(aLogRegion);
  OT_UNUSED_VARIABLE(aFormat);
}

/***************************************************************************//**
 * Initialize application.
 ******************************************************************************/
void app_init(void)
{
  app_log("------DALI+ Main Device using Thread example!------\r\n");
  if ((otSetStateChangedCallback(get_daliplus_instance(),
                                 netif_state_changed_cb,
                                 get_daliplus_instance()) == OT_ERROR_NONE)
      && (daliplus_init(DALIPLUS_ROLE_MAIN_DEVICE) == DALIPLUS_ERROR_NONE)) {
    app_log("%s\r\n%s\r\n%s\r\n",
            "Main device: Done initializing Thread network parameters",
            "Main device: Done enabling Thread network",
            "Main device: Done setting up CoAP");
    return;
  }
  app_log_error("Main device: Failed to initialize Thread network parameters,"
                " resetting...\r\n");
  otInstanceFactoryReset(get_daliplus_instance());
}

/***************************************************************************//**
 * App ticking function.
 ******************************************************************************/
void app_process_action(void)
{
  otTaskletsProcess(get_daliplus_instance());
  otSysProcessDrivers(get_daliplus_instance());

  if (check_encrypted) {
    app_log("Main device: Now sending %s packet\r\n",
            (is_encrypted == true) ? "encrypted" : "normal");
    check_encrypted = false;
  }

  if (send_flag) {
    app_log("Main device: Message sent 0x%02X\r\n",
            daliplus_forward_coap_message(is_encrypted,
                                          &device_list[0].deviceIP6Address,
                                          &fwd_msg));
  }
  send_flag = false;
}

void daliplus_request_cb(void *aContext,
                         otMessage *aMessage,
                         const otMessageInfo *aMessageInfo)
{
  OT_UNUSED_VARIABLE(aContext);
  // Extract CoAP message type and code
  otCoapCode msg_code = otCoapMessageGetCode(aMessage);
  otCoapType msg_type = otCoapMessageGetType(aMessage);
  // Buffer to store the received payload
  uint8_t daliplus_payload[128] = { 0 };
  // Read the payload from the received message
  uint16_t daliplus_length = otMessageRead(aMessage,
                                           otMessageGetOffset(aMessage),
                                           daliplus_payload,
                                           sizeof(daliplus_payload));
  // Check if the message is a Non-Confirmable POST request
  if ((msg_type == OT_COAP_TYPE_NON_CONFIRMABLE)
      && (msg_code == OT_COAP_CODE_POST)) {
    // Update sequence number based on payload content
    update_ndu_sequence(((daliplus_payload[3] << 8)
                         | (daliplus_payload[4] & 0xFF)));
    // If the message does not indicate a new joiner device, just display it and return
    if (!(daliplus_payload[1] & 0x10)) {
      daliplus_display_received_message(DALIPLUS_PACKET_BACKWARD,
                                        daliplus_payload,
                                        daliplus_length);
      return;
    }

    // Register the new joiner device
    device_list[daliplus_device_index].deviceRole =
      DALIPLUS_ROLE_SECONDARY_DEVICE;
    // Copy EUI-64 address from the payload
    memcpy(device_list[daliplus_device_index].deviceEUI64,
           &daliplus_payload[9],
           OT_EXT_ADDRESS_SIZE);

    // Copy IPv6 address from the payload
    memcpy(&device_list[daliplus_device_index].deviceIP6Address,
           &aMessageInfo->mPeerAddr,
           OT_IP6_ADDRESS_SIZE);

    // Log the newly joined device's EUI64
    app_log("Joiner joined with EUI64: 0x");
    for (size_t i = 0; i < OT_EXT_ADDRESS_SIZE; i++) {
      app_log("%02X", device_list[daliplus_device_index].deviceEUI64[i]);
    }
    app_log("\r\n%s\r\n%s\r\n",
            "Main device: Press button 0 to change whether packet is sent"
            " with encryption or not, button 1 to send the packet",
            "Main device: Sending UDP network configuration!");

    // Prepare the network configuration frame
    char octet[2];
    uint8_t network_config_frame[26] = { 0 };
    uint8_t bindKey[] = DALIPLUS_BIND_KEY_CONTENT;

    // Fill network configuration frame
    network_config_frame[0] = 0x00;   // CDU Flags - R bit field
    network_config_frame[1] = 0x1F;   // CDU flags - KACIU bits field
    network_config_frame[2] = 0x12;   // Sub-net region high byte
    network_config_frame[3] = 0x34;   // Sub-net region low byte
    network_config_frame[4] = daliplus_device_index >> 8;   // Device index (high byte)
    network_config_frame[5] = (uint8_t)daliplus_device_index & 0xFF;   // Device index (low byte)
    network_config_frame[6] = 0x04;   // Multi-cast scope
    network_config_frame[7] = 0x01;   // Sender key
    network_config_frame[8] = 0x01;   // Encryption key ID
    network_config_frame[9] = 0x01;   // Access permission

    // Convert the binding key into the network configuration frame
    for (uint16_t i = 0; i < DALIPLUS_BIND_KEY_LENGTH; i++) {
      memcpy(octet, (uint8_t *)&bindKey[2 * i], 2);
      network_config_frame[i + 10] = (uint8_t)strtol(octet, NULL, 16);
    }

    // Prepare network message structure
    daliplus_message_t network_msg_info = { DALIPLUS_PACKET_NETWORK_CONFIG,
                                            network_config_frame,
                                            sizeof(network_config_frame) };

    app_log("Main device: Sent UDP network configuration 0x%02X!\r\n",
            daliplus_forward_coap_message(false,
                                          &device_list[daliplus_device_index].
                                          deviceIP6Address,
                                          &network_msg_info));
    // Increment device index for next joiner
    daliplus_device_index++;
  }
}

void daliplus_response_cb(void *aContext,
                          otMessage *aMessage,
                          const otMessageInfo *aMessageInfo,
                          otError aResult)
{
  OT_UNUSED_VARIABLE(aContext);
  OT_UNUSED_VARIABLE(aMessageInfo);
  uint8_t daliplus_bind_key[DALIPLUS_BIND_KEY_LENGTH];
  uint8_t daliplus_backward_payload[128] = { 0 };
  uint8_t daliplus_decrypted_msg[128] = { 0 };
  uint16_t daliplus_decrypted_msg_size = 0;
  uint16_t daliplus_backward_len = 0;
  otCoapCode msg_code = otCoapMessageGetCode(aMessage);
  otCoapType msg_type = otCoapMessageGetType(aMessage);

  if (aResult != OT_ERROR_NONE) {
    app_log_error("Main device: Error,"
                  " delivery not confirmed: %d\r\n", aResult);
    return;
  }

  if ((msg_code == OT_COAP_CODE_VALID)
      && (msg_type == OT_COAP_TYPE_ACKNOWLEDGMENT)) {
    daliplus_display_received_message(DALIPLUS_PACKET_ACK,
                                      daliplus_backward_payload,
                                      daliplus_backward_len);
    return;
  }

  daliplus_backward_len = otMessageRead(aMessage,
                                        otMessageGetOffset(aMessage),
                                        daliplus_backward_payload,
                                        sizeof(daliplus_backward_payload));

  if (daliplus_backward_payload[0] != DALIPLUS_PACKET_NONENCRYPTED) {
    daliplus_display_received_message(DALIPLUS_PACKET_ENCRYPTED,
                                      daliplus_backward_payload,
                                      daliplus_backward_len);
    daliplus_read_nvm_var(NVM3_UDP_ENCRYPTION_KEY_SLOT,
                          daliplus_bind_key,
                          DALIPLUS_BIND_KEY_LENGTH);

    app_log("Main device: Decrypting message...\r\n");
    daliplus_decrypt_message(daliplus_bind_key,
                             daliplus_backward_payload,
                             daliplus_backward_len,
                             daliplus_decrypted_msg,
                             &daliplus_decrypted_msg_size);

    app_log("Main device: Decrypted message 0x");
    for (uint16_t i = 0; i < daliplus_decrypted_msg_size; i++) {
      app_log("%02X", daliplus_decrypted_msg[i]);
    }
    app_log("\r\n");
    return;
  }

  switch (msg_type)
  {
    case OT_COAP_TYPE_NON_CONFIRMABLE:
      daliplus_display_received_message(DALIPLUS_PACKET_BACKWARD,
                                        daliplus_backward_payload,
                                        daliplus_backward_len);
      break;

    case OT_COAP_TYPE_ACKNOWLEDGMENT:
      if (msg_code == OT_COAP_CODE_CHANGED) {
        daliplus_display_received_message(DALIPLUS_PACKET_ACK_ERROR,
                                          daliplus_backward_payload,
                                          daliplus_backward_len);
      }
      break;

    default:
      app_log_error("Main device: Wrong message type: %d,"
                    " discarding response message...!\r\n",
                    msg_type);
      break;
  }
}

void netif_state_changed_cb(otChangedFlags aFlags, void *aContext)
{
  if (aFlags & OT_CHANGED_THREAD_ROLE) {
    otDeviceRole changedRole = otThreadGetDeviceRole(aContext);
    switch (changedRole)
    {
      case OT_DEVICE_ROLE_LEADER:
        app_log("Main device: Become leader\r\n");
        if (otCommissionerStart(get_daliplus_instance(), NULL,
                                NULL,
                                get_daliplus_instance()) != OT_ERROR_NONE) {
          app_log("Main device: Failed to start commissioner\r\n");
          return;
        }
        break;

      default:
        otThreadSetLocalLeaderWeight(get_daliplus_instance(), 255);
        app_log("Main device: Please wait until"
                " the device changes into leader 0x%02X\r\n",
                otThreadBecomeLeader(get_daliplus_instance()));
        break;
    }
    return;
  }
  otCommissionerState changedState = otCommissionerGetState(
    get_daliplus_instance());
  if ((aFlags & OT_CHANGED_COMMISSIONER_STATE)
      && (changedState == OT_COMMISSIONER_STATE_ACTIVE)) {
    // It shall allow Joiner to join for a duration of 120s
    app_log(
      "Main device: Commissioner role achieved, adding joiner 0x%02X!\r\n",
      otCommissionerAddJoiner(get_daliplus_instance(),
                              NULL, DALIPLUS_INPUT_DEVICE_PSK, 120));

    app_log("%s\r\n",
            "Main device: Waiting secondary device to join (duration: 120s)");
  }
}

void daliplus_display_received_message(daliplus_packet_t packetType,
                                       uint8_t *packetPayload,
                                       uint16_t payloadLength)
{
  uint16_t daliplus_index = 0;
  uint8_t daliplus_buffer[payloadLength];
  // Copy the packet payload into a local buffer
  memcpy(daliplus_buffer, packetPayload, payloadLength);
  // If the packet is an acknowledgment, log a success message and return
  if (packetType == DALIPLUS_PACKET_ACK) {
    app_log("Main device: Delivery confirmed!\r\n");
    return;
  }
  // Ensure that the packet is not too short to process
  if (payloadLength < 8) {
    app_log("Main device: CoAP message is too short (%d bytes)\n",
            payloadLength);
    return;
  }
  // Handle encrypted messages (Key ID != 0xDA)
  if ((packetPayload[0] != DALIPLUS_PACKET_NONENCRYPTED)
      && (packetType == DALIPLUS_PACKET_ENCRYPTED)) {
    app_log("Main device: Got encrypted CoAP message:\n");
    // Log packet metadata
    app_log("  - Key ID: 0x%02X\n", daliplus_buffer[daliplus_index++]);
    app_log("  - Sub-net: 0x%02X%02X\n", daliplus_buffer[daliplus_index],
            daliplus_buffer[daliplus_index + 1]);
    daliplus_index += 2;
    app_log("  - Sender ID: 0x%02X%02X\n", daliplus_buffer[daliplus_index],
            daliplus_buffer[daliplus_index + 1]);
    daliplus_index += 2;
    app_log("  - Frame Counter: 0x%02X%02X%02X%02X%02X\r\n",
            daliplus_buffer[daliplus_index],
            daliplus_buffer[daliplus_index + 1],
            daliplus_buffer[daliplus_index + 2],
            daliplus_buffer[daliplus_index + 3],
            daliplus_buffer[daliplus_index + 4]);
    daliplus_index += 5;
    // Log authentication field (8 bytes)
    app_log("  - Authentication field: 0x");
    for (uint8_t i = 0; i < 8; i++)
    {
      app_log("%02X", daliplus_buffer[daliplus_index++]);
    }
    app_log("\r\n");
    // Log the encrypted message content
    app_log("  - Encrypted message:");
    for (uint16_t i = daliplus_index; i < payloadLength; i++)
    {
      app_log("%02X", daliplus_buffer[daliplus_index++]);
    }
    app_log("\r\n");
    return;
  }
  // Process different packet types
  switch (packetType)
  {
    case DALIPLUS_PACKET_FORWARD:
    case DALIPLUS_PACKET_BACKWARD:
      app_log("Main device: Got %s CoAP message:\n",
              (packetType == DALIPLUS_PACKET_FORWARD) ? "forward" : "backward");
      // Extract and log message metadata
      app_log("  - Key ID: 0x%02X\n", daliplus_buffer[daliplus_index++]);
      app_log("  - NDU Length: 0x%02X\n", daliplus_buffer[daliplus_index++]);
      app_log("  - NDU Flags: 0x%02X\n", daliplus_buffer[daliplus_index++]);
      app_log("  - NDU Sequence: 0x%02X%02X\n", daliplus_buffer[daliplus_index],
              daliplus_buffer[daliplus_index + 1]);
      daliplus_index += 2;
      app_log("  - System Address: 0x%02X\n",
              daliplus_buffer[daliplus_index++]);
      // Extract ADU Length (last 2 bits of the first byte and full second byte)
      uint16_t aduLength = ((daliplus_buffer[daliplus_index++] & 0x03) << 8);
      aduLength |= daliplus_buffer[daliplus_index++];
      app_log("  - ADU Length: %d\n  - ADU Data: ", aduLength);
      // Log ADU data
      for (size_t i = 0; i < aduLength && daliplus_index < payloadLength; i++)
      {
        app_log("%02X", daliplus_buffer[daliplus_index++]);
      }
      app_log("\n");
      break;
    case DALIPLUS_PACKET_DISCOVERY:
    case DALIPLUS_PACKET_NETWORK_CONFIG:
      app_log("Main device: Got %s CoAP message:\n",
              (packetType
               == DALIPLUS_PACKET_DISCOVERY) ? "discovery" : "network configuration");
      // Extract and log message metadata
      app_log("  - Key ID: 0x%02X\n", daliplus_buffer[daliplus_index++]);
      app_log("  - NDU Length: 0x%02X\n", daliplus_buffer[daliplus_index++]);
      app_log("  - NDU Flags: 0x%02X\n", daliplus_buffer[daliplus_index++]);
      app_log("  - NDU Sequence: 0x%02X%02X\n", daliplus_buffer[daliplus_index],
              daliplus_buffer[daliplus_index + 1]);
      daliplus_index += 2;
      app_log("  - System Address: 0x%02X\n",
              daliplus_buffer[daliplus_index++]);
      // Extract and log CDU/DDU Length
      uint16_t length = ((daliplus_buffer[daliplus_index++] & 0x03) << 8);
      length |= daliplus_buffer[daliplus_index++];
      app_log("  - %s Length: %d\n",
              (packetType == DALIPLUS_PACKET_DISCOVERY) ? "DDU" : "CDU",
              length);
      // Extract and log CDU/DDU Flags
      app_log("  - %s Flags: 0x%02X\n",
              (packetType == DALIPLUS_PACKET_DISCOVERY) ? "DDU" : "CDU",
              daliplus_buffer[daliplus_index++]);
      // Log CDU/DDU Data
      app_log("  - %s Data: ",
              (packetType == DALIPLUS_PACKET_DISCOVERY) ? "DDU" : "CDU");
      for (size_t i = 0; i < length && daliplus_index < payloadLength; i++)
      {
        app_log("%02X", daliplus_buffer[daliplus_index++]);
      }
      app_log("\n");
      break;
    case DALIPLUS_PACKET_ACK_ERROR:
      app_log("Main device: Got ACK with error CoAP message with:\n");
      // Extract and log error message metadata
      app_log("  - Key ID: 0x%02X\n", daliplus_buffer[daliplus_index++]);
      app_log("  - NDU Length: 0x%02X\n", daliplus_buffer[daliplus_index++]);
      app_log("  - NDU Flags: 0x%02X\n", daliplus_buffer[daliplus_index++]);
      app_log("  - NDU Sequence: 0x%02X%02X\n", daliplus_buffer[daliplus_index],
              daliplus_buffer[daliplus_index + 1]);
      daliplus_index += 2;
      app_log("  - System Address: 0x%02X\n",
              daliplus_buffer[daliplus_index++]);
      // Extract and log error indicator
      app_log("  - Error Indicator: 0x%02X%02X\n",
              daliplus_buffer[daliplus_index],
              daliplus_buffer[daliplus_index + 1]);
      daliplus_index += 2;
      break;
    default:
      // Log an error if an invalid packet type is received
      app_log("Main device: Invalid DALI+ packet type!\r\n");
      break;
  }
}

void sl_button_on_change(const sl_button_t *handle)
{
  if ((sl_button_get_state(handle) == SL_SIMPLE_BUTTON_PRESSED)
      && (SL_SIMPLE_BUTTON_INSTANCE(0) == handle)) {
    is_encrypted = !is_encrypted;
    check_encrypted = !check_encrypted;
  }
  if ((sl_button_get_state(handle) == SL_SIMPLE_BUTTON_PRESSED)
      && (SL_SIMPLE_BUTTON_INSTANCE(1) == handle)) {
    send_flag = true;
  }
}
