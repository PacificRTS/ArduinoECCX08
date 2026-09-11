/*
  This file is part of the ArduinoECCX08 library.
  Copyright (c) 2018 Arduino SA. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <Arduino.h>

#if defined(ARDUINO_ARCH_ESP8266)
#include <twi.h>
#endif

#include "ECCX08.h"

// The longest packet the driver sends. Verify(External) carries a 64 byte signature
// and a 64 byte public key inside the 8 bytes of framing every command has, which is
// 8 bytes past the 128 byte transmit buffer an Arduino Wire gives you by default.
#define ECCX08_MAX_PACKET_SIZE (8 + 128)

const uint32_t ECCX08Class::_wakeupFrequency = 100000u;  // 100 kHz
#ifdef __AVR__
const uint32_t ECCX08Class::_normalFrequency = 400000u;  // 400 kHz
#elif defined(ARDUINO_ARCH_ZEPHYR) && defined(ARDUINO_PORTENTA_H7_M7)
// FIXME speed above 400kHz require manual configuration in stm32 running on zephyr
const uint32_t ECCX08Class::_normalFrequency = 400000u;
#else
const uint32_t ECCX08Class::_normalFrequency = 1000000u; // 1 MHz
#endif

ECCX08Class::ECCX08Class(TwoWire& wire, uint8_t address) :
  _wire(&wire),
  _address(address)
{
}

ECCX08Class::~ECCX08Class()
{
}

int ECCX08Class::begin(uint8_t i2cAddress)
{
  _address = i2cAddress;
  return begin();
}

int ECCX08Class::begin()
{
#if defined(WIRE_HAS_BUFFER_SIZE)
  // Asked for before begin(), which is where the buffer actually gets allocated.
  _wire->setBufferSize(ECCX08_MAX_PACKET_SIZE);
#endif

  _wire->begin();

  wakeup();
  idle();
  
  long ver = version() & 0x0F00000;

  if (ver != 0x0500000 && ver != 0x0600000) {
    return 0;
  }

  return 1;
}

void ECCX08Class::end()
{
  // First wake up the device otherwise the chip didn't react to a sleep command
  wakeup();
  sleep();
#ifdef WIRE_HAS_END
  _wire->end();
#endif
}

int ECCX08Class::serialNumber(byte sn[], size_t len)
{
  if(len < 12) {
    return 0;
  }

  if (!read(0, 0, &sn[0], 4)) {
    return 0;
  }

  if (!read(0, 2, &sn[4], 4)) {
    return 0;
  }

  if (!read(0, 3, &sn[8], 4)) {
    return 0;
  }

  return 1;
}

String ECCX08Class::serialNumber()
{
  String result = (char*)NULL;
  byte sn[12];

  if (!serialNumber(sn)) {
    return result;
  }

  result.reserve(18);

  for (int i = 0; i < 9; i++) {
    byte b = sn[i];

    if (b < 16) {
      result += "0";
    }
    result += String(b, HEX);
  }

  result.toUpperCase();

  return result;
}

long ECCX08Class::random(long max)
{
  return random(0, max);
}

long ECCX08Class::random(long min, long max)
{
  if (min >= max)
  {
    return min;
  }

  long diff = max - min;

  long r;
  random((byte*)&r, sizeof(r));

  if (r < 0) {
    r = -r;
  }

  r = (r % diff);

  return (r + min);
}

int ECCX08Class::random(byte data[], size_t length)
{
  if (!wakeup()) {
    return 0;
  }

  while (length) {
    if (!sendCommand(0x1b, 0x00, 0x0000)) {
      return 0;
    }

    delay(23);

    byte response[32];

    if (!receiveResponse(response, sizeof(response))) {
      return 0;
    }

    int copyLength = min(32, (int)length);
    memcpy(data, response, copyLength);

    length -= copyLength;
    data += copyLength;
  }

  delay(1);

  idle();

  return 1;
}

int ECCX08Class::generatePrivateKey(int slot, byte publicKey[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x40, 0x04, slot)) {
    return 0;
  }

  delay(115);

  if (!receiveResponse(publicKey, 64)) {
    return 0;
  }

  delay(1);

  idle();

  return 1;
}

int ECCX08Class::generatePublicKey(int slot, byte publicKey[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x40, 0x00, slot)) {
    return 0;
  }

  delay(115);

  if (!receiveResponse(publicKey, 64)) {
    return 0;
  }

  delay(1);

  idle();

  return 1;
}

int ECCX08Class::ecdsaVerify(const byte message[], const byte signature[], const byte pubkey[])
{
  if (!challenge(message)) {
    return 0;
  }

  if (!verify(signature, pubkey)) {
    return 0;
  }

  return 1;
}

/*
  Sign the 32 byte digest in message[] with the private key held in slot.

  The digest is loaded into TempKey with a pass-through Nonce and then signed in
  external message mode. That requires the slot's KeyConfig.ReqRandom to be 0: with
  ReqRandom set, the device will only sign a TempKey it derived from its own RNG
  output, so an externally agreed digest cannot be signed at all.

  The discarded Random command that used to open this function has been removed. It
  fed nothing: the pass-through Nonce below overwrites TempKey either way, and it
  does not satisfy ReqRandom, which needs Nonce in random mode instead.
*/
int ECCX08Class::ecSign(int slot, const byte message[], byte signature[])
{
  // Load the digest to be signed into TempKey.
  if (!challenge(message)) {
    return 0;
  }

  // Sign the contents of TempKey with the slot's private key.
  if (!sign(slot, signature)) {
    return 0;
  }

  return 1;
}

int ECCX08Class::SHA256(const uint8_t *buffer, size_t size, uint8_t *digest)
{
  beginSHA256();
  uint8_t * cursor = (uint8_t*)buffer;
  uint32_t bytes_read = 0;

  for(; bytes_read + 64 <= size; bytes_read += 64, cursor += 64) {
    updateSHA256(cursor);
  }
  return endSHA256(cursor, size - bytes_read, digest);
}

int ECCX08Class::beginSHA256()
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x47, 0x00, 0x0000)) {
    return 0;
  }

  delay(9);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int ECCX08Class::updateSHA256(const byte data[])
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x47, 0x01, 64, data, 64)) {
    return 0;
  }

  delay(9);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int ECCX08Class::endSHA256(byte result[])
{
  return endSHA256(NULL, 0, result);
}

int ECCX08Class::endSHA256(const byte data[], int length, byte result[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x47, 0x02, length, data, length)) {
    return 0;
  }

  delay(9);

  if (!receiveResponse(result, 32)) {
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

int ECCX08Class::readSlot(int slot, byte data[], int length)
{
  if (slot < 0 || slot > 15) {
    return -1;
  }

  if (length % 4 != 0) {
    return 0;
  }

  int chunkSize = 32;

  for (int i = 0; i < length; i += chunkSize) {
    if ((length - i) < 32) {
      chunkSize = 4;
    }

    if (!read(2, addressForSlotOffset(slot, i), &data[i], chunkSize)) {
      return 0;
    }
  }

  return 1;
}

int ECCX08Class::writeSlot(int slot, const byte data[], int length)
{
  if (slot < 0 || slot > 15) {
    return -1;
  }

  if (length % 4 != 0) {
    return 0;
  }

  int chunkSize = 32;

  for (int i = 0; i < length; i += chunkSize) {
    if ((length - i) < 32) {
      chunkSize = 4;
    }

    if (!write(2, addressForSlotOffset(slot, i), &data[i], chunkSize)) {
      return 0;
    }
  }

  return 1;
}

int ECCX08Class::locked()
{
  byte config[4];

  if (!read(0, 0x15, config, sizeof(config))) {
    return 0;
  }

  if (config[2] == 0x00 && config[3] == 0x00) {
    return 1; // locked
  }

  return 0;
}

int ECCX08Class::writeConfiguration(const byte data[])
{
  // skip first 16 bytes, they are not writable
  for (int i = 16; i < 128; i += 4) {
    if (i == 84) {
      // not writable
      continue;
    }

    if (!write(0, i / 4, &data[i], 4)) {
      return 0;
    }
  }

  return 1;
}

int ECCX08Class::readConfiguration(byte data[])
{
  for (int i = 0; i < 128; i += 32) {
    if (!read(0, i / 4, &data[i], 32)) {
      return 0;
    }
  }

  return 1;
}

int ECCX08Class::lock()
{
  // lock config
  if (!lock(0)) {
    return 0;
  }

  // lock data and OTP
  if (!lock(1)) {
    return 0;
  }

  return 1;
}

int ECCX08Class::lockConfigZone()
{
  // Lock mode 0: the configuration zone.
  return lock(0);
}

int ECCX08Class::lockDataZone()
{
  // Lock mode 1: the data and OTP zones.
  return lock(1);
}

int ECCX08Class::lockSlot(int slot)
{
  if (slot < 0 || slot > 15) {
    return 0;
  }

  // Lock mode 2 locks a single slot, with the slot number in bits 2-5. The slot's
  // KeyConfig.Lockable must be 1 and the data zone must already be locked.
  return lock(0x02 | (slot << 2));
}


int ECCX08Class::beginHMAC(uint16_t keySlot)
{
  // HMAC implementation is only for ATECC608
  uint8_t status;
  long ecc608ver = 0x0600000;
  long eccCurrVer = version() & 0x0F00000;
  
  if (eccCurrVer != ecc608ver) {
    return 0;
  }

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x47, 0x04, keySlot)) {
    return 0;
  }

  delay(9);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int ECCX08Class::updateHMAC(const byte data[], int length) {
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  // Processing message
  int currLength = 0;
  while (length) {
    data += currLength;

    if (length > 64) {
      currLength = 64;
    } else {
      currLength = length;
    }
    length -= currLength;
    
    if (!sendCommand(0x47, 0x01, currLength, data, currLength)) {
      return 0;
    }

    delay(9);

    if (!receiveResponse(&status, sizeof(status))) {
      return 0;
    }

    delay(1);
  }
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int ECCX08Class::endHMAC(byte result[])
{
  return endHMAC(NULL, 0, result);
}

int ECCX08Class::endHMAC(const byte data[], int length, byte result[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x47, 0x02, length, data, length)) {
    return 0;
  }

  delay(9);

  if (!receiveResponse(result, 32)) {
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

int ECCX08Class::nonce(const byte data[])
{
  return challenge(data);
}

int ECCX08Class::generateEphemeralPublicKey(byte publicKey[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x40, 0x04, 0xFFFF)) {
    idle();
    return 0;
  }

  // GenKey is relatively slow: 215 ms worst case.
  delay(220);

  if (!receiveResponse(publicKey, 64)) {
    idle();
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

// TODO: Add an ECDH variant that leaves the shared secret in TempKey (mode 0x09)
int ECCX08Class::ecdh(int slot, const byte peerPublicKey[], byte sharedSecret[])
{
  if (slot < 0 || slot > 15) {
    return 0;
  }

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x43, 0x0C, (uint16_t)slot, peerPublicKey, 64)) {
    idle();
    return 0;
  }

  // ECDH takes up to 172 ms.
  delay(180);

  if (!receiveResponse(sharedSecret, 32)) {
    idle();
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

int ECCX08Class::ecdhTempKey( const byte peerPublicKey[], byte sharedSecret[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x43, 0x0D, 0x0000, peerPublicKey, 64)) {
    idle();
    return 0;
  }

  // ECDH takes up to 172 ms.
  delay(180);

  if (!receiveResponse(sharedSecret, 32)) {
    idle();
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

int ECCX08Class::kdf(uint16_t keySlot, const byte message[], byte outputData[], size_t messageLength, uint8_t mode)
{
  if (keySlot > 15) {
    return 0;
  }

  // The message length is encoded in the MSB of Details, so it must fit in a byte,
  // and the message itself has to fit in the data field of the KDF command.
  if (message == NULL || messageLength == 0 || messageLength > 128) {
    return 0;
  }

  if (!wakeup()) {
    return 0;
  }

  byte data[4 + 128];

  // Details[0..2]: algorithm specific options. For HKDF, bits 0-1 select where the
  // message lives; 0x02 = "in the input parameter", i.e. the bytes appended below.
  data[0] = 0x02;
  data[1] = 0x00;
  data[2] = 0x00;
  // Details[3]: the message length in bytes, for every algorithm except AES.
  data[3] = (byte)messageLength;

  memcpy(&data[4], message, messageLength);

  if (!sendCommand(0x56, mode, keySlot, data, 4 + messageLength)) {
    idle();
    return 0;
  }

  // KDF is the slowest command on the device: 165 ms worst case.
  delay(170);

  if (!receiveResponse(outputData, 32)) {
    idle();
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

int ECCX08Class::incrementCounter(int counterId, long& counter)
{
  if (counterId < 0 || counterId > 1) {
    return 0;
  }

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x24, 1, counterId)) {
    return 0;
  }

  delay(20);

  if (!receiveResponse(&counter, sizeof(counter))) {
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

long ECCX08Class::incrementCounter(int counterId)
{
  long counter;  // the counter can go up to 2,097,151

  if(!incrementCounter(counterId, counter)) {
    return -1;
  }

  return counter;
}

int ECCX08Class::readCounter(int counterId, long& counter)
{
  if (counterId < 0 || counterId > 1) {
    return 0;
  }

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x24, 0, counterId)) {
    return 0;
  }

  delay(20);

  if (!receiveResponse(&counter, sizeof(counter))) {
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

long ECCX08Class::readCounter(int counterId)
{
  long counter;  // the counter can go up to 2,097,151

  if(!readCounter(counterId, counter)) {
    return -1;
  }

  return counter;
}

int ECCX08Class::wakeup()
{
  _wire->setClock(_wakeupFrequency);
  _wire->beginTransmission(0x00);
  _wire->endTransmission();

  delayMicroseconds(1500);

  byte response;

  if (!receiveResponse(&response, sizeof(response)) || response != 0x11) {
    return 0;
  }

  _wire->setClock(_normalFrequency);

  return 1;
}

int ECCX08Class::sleep()
{
  _wire->beginTransmission(_address);
  _wire->write(0x01);

  if (_wire->endTransmission() != 0) {
    return 0;
  }

  delay(1);

  return 1;
}

int ECCX08Class::idle()
{
  _wire->beginTransmission(_address);
  _wire->write(0x02);

  if (_wire->endTransmission() != 0) {
    return 0;
  }

  delay(1);

  return 1;
}

long ECCX08Class::version()
{
  uint32_t version = 0;

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x30, 0x00, 0x0000)) {
    return 0;
  }

  delay(2);

  if (!receiveResponse(&version, sizeof(version))) {
    return 0;
  }

  delay(1);
  idle();

  return version;
}

int ECCX08Class::challenge(const byte message[])
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  // Nonce, pass through
  if (!sendCommand(0x16, 0x03, 0x0000, message, 32)) {
    return 0;
  }

  delay(29);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int ECCX08Class::verify(const byte signature[], const byte pubkey[])
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  byte data[128];
  memcpy(&data[0], signature, 64);
  memcpy(&data[64], pubkey, 64);

  // Verify, external, P256
  if (!sendCommand(0x45, 0x02, 0x0004, data, sizeof(data))) {
    return 0;
  }

  // Verify takes up to 295 ms.
  delay(300);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int ECCX08Class::sign(int slot, byte signature[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x41, 0x80, slot)) {
    return 0;
  }

  // Sign takes up to 220 ms.
  delay(230);

  if (!receiveResponse(signature, 64)) {
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

int ECCX08Class::read(int zone, int address, byte buffer[], int length)
{
  if (!wakeup()) {
    return 0;
  }

  if (length != 4 && length != 32) {
    return 0;
  }

  if (length == 32) {
    zone |= 0x80;
  }

  if (!sendCommand(0x02, zone, address)) {
    return 0;
  }

  delay(5);

  if (!receiveResponse(buffer, length)) {
    return 0;
  }

  delay(1);
  idle();

  return length;
}

int ECCX08Class::write(int zone, int address, const byte buffer[], int length)
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  if (length != 4 && length != 32) {
    return 0;
  }

  if (length == 32) {
    zone |= 0x80;
  }

  if (!sendCommand(0x12, zone, address, buffer, length)) {
    return 0;
  }

  delay(26);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int ECCX08Class::lock(int mode)
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  // Bit 7 of Mode tells the device to skip the CRC summary check of the zone
  // contents, so no expected-contents CRC has to be supplied in Param2.
  if (!sendCommand(0x17, 0x80 | mode, 0x0000)) {
    return 0;
  }

  delay(32);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int ECCX08Class::addressForSlotOffset(int slot, int offset)
{
  int block = offset / 32;
  offset = (offset % 32) / 4;  

  return (slot << 3) | (block << 8) | (offset);
}

// TODO: Replace each caller's fixed worst-case delay() with a polled read of the response
int ECCX08Class::sendCommand(uint8_t opcode, uint8_t param1, uint16_t param2, const byte data[], size_t dataLength)
{
  int commandLength = 8 + dataLength; // 1 for type, 1 for length, 1 for opcode, 1 for param1, 2 for param2, 2 for CRC
  byte command[commandLength]; 
  
  command[0] = 0x03;
  command[1] = sizeof(command) - 1;
  command[2] = opcode;
  command[3] = param1;
  memcpy(&command[4], &param2, sizeof(param2));
  memcpy(&command[6], data, dataLength);

  uint16_t crc = crc16(&command[1], 8 - 3 + dataLength);
  memcpy(&command[6 + dataLength], &crc, sizeof(crc));

#if defined(ARDUINO_ARCH_ESP8266)
  // The ESP8266 core fixes its Wire transmit buffer at 128 bytes and offers no way to
  // grow it, so a Verify(External) cannot go out through Wire at all. The low-level
  // TWI call writes straight from the caller's buffer and has no such limit.
  if (twi_writeTo(_address, command, commandLength, true) != 0) {
    return 0;
  }
#else
  _wire->beginTransmission(_address);

  // Wire quietly drops whatever will not fit its transmit buffer, and the chip ACKs
  // the truncated packet, so endTransmission() still reports success. Left unchecked
  // the device answers the short packet with a parse error, which reads back as an
  // ordinary refusal and sends you looking at the wrong thing entirely.
  if (_wire->write(command, commandLength) != (size_t)commandLength) {
    _wire->endTransmission();
    return 0;
  }

  if (_wire->endTransmission() != 0) {
    return 0;
  }
#endif

  return 1;
}

// TODO: Surface the device status byte instead of collapsing every result to 0/1
int ECCX08Class::receiveResponse(void* response, size_t length)
{
  int retries = 20;
  size_t responseSize = length + 3; // 1 for length header, 2 for CRC
  byte responseBuffer[responseSize];

  while (_wire->requestFrom((uint8_t)_address, (size_t)responseSize, (bool)true) != responseSize && retries--);

  responseBuffer[0] = _wire->read();

  // make sure length matches
  if (responseBuffer[0] != responseSize) {
    // Clear the buffer
    for (size_t i = 1; _wire->available(); i++) {
      (void) _wire->read();
    }
    delay(1);
    idle();
    return 0;
  }

  for (size_t i = 1; _wire->available(); i++) {
    responseBuffer[i] = _wire->read();
  }

  // verify CRC
  uint16_t responseCrc = responseBuffer[length + 1] | (responseBuffer[length + 2] << 8);
  if (responseCrc != crc16(responseBuffer, responseSize - 2)) {
    delay(1);
    idle();
    return 0;
  }

  memcpy(response, &responseBuffer[1], length);

  return 1;
}

uint16_t ECCX08Class::crc16(const byte data[], size_t length)
{
  if (data == NULL || length == 0) {
    return 0;
  }

  uint16_t crc = 0;

  while (length) {
    byte b = *data;

    for (uint8_t shift = 0x01; shift > 0x00; shift <<= 1) {
      uint8_t dataBit = (b & shift) ? 1 : 0;
      uint8_t crcBit = crc >> 15;

      crc <<= 1;
      
      if (dataBit != crcBit) {
        crc ^= 0x8005;
      }
    }

    length--;
    data++;
  }

  return crc;
}

#if __ZEPHYR__
  #ifndef CRYPTO_WIRE
    #define CRYPTO_WIRE Wire1
  #endif
#endif

#ifdef CRYPTO_WIRE
ECCX08Class ECCX08(CRYPTO_WIRE, 0x60);
#else
ECCX08Class ECCX08(Wire, 0x60);
#endif
