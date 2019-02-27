#include <string.h>

#include <ESP8266HTTPClient.h>
#include <ESP8266WiFi.h>
#include <MFRC522.h>
#include <SPI.h>

#include <user_interface.h>
#include <wpa2_enterprise.h>

/* create a super_secret_password_definitions.h that defines:
 * SUPER_SECRET_SSID
 * SUPER_SECRET_USERNAME
 * SUPER_SECRET_PASSWORD
 */
#include "super_secret_password_definition.h"

#define ERR_OK 0
#define ERR_NOMEM 1

#define BAUD 9600
#define PROTOCOL "http"
#define HOST "vro"
#define THIS_LOCATION 1

MFRC522 mfrc522;  // Create MFRC522 instance
MFRC522::MIFARE_Key key;

void setup() {
  Serial.begin(BAUD);
  while (!Serial);
  
  initMFRC522(&mfrc522, &key);
  wpaConnect(SUPER_SECRET_SSID, SUPER_SECRET_PASSWORD);

  Serial.printf("setup: complete\n");
}

void loop() {
  // In this sample we use the second sector,
  // that is: sector #1, covering block #4 up to and including block #7
  char sector = 1;
  char blockAddr = 4;
  MFRC522::StatusCode status;
  byte buffer[18];
  byte size = sizeof(buffer);

  // Look for new cards
  if (!mfrc522.PICC_IsNewCardPresent()) {
    return;
  }

  // Select one of the cards
  if (!mfrc522.PICC_ReadCardSerial()) {
    return;
  }
  Serial.println("Authenticating using key A...");
  status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockAddr, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  status = (MFRC522::StatusCode)mfrc522.MIFARE_Read(blockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("MIFARE_Read() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }

  uint32_t userId;
  to_uint32_t(&userId, (uint8_t*)buffer);

  char encounterUrl[1024];
  mkEncounterUrl(encounterUrl, 1024, PROTOCOL, HOST, "in", THIS_LOCATION,
                 userId);
  httpGet(encounterUrl);

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
}

void mkEncounterUrl(char* dest, size_t destlen, char* protocol, char* host,
                    char* eventType, uint32_t locationId, uint32_t userId) {
  snprintf(dest, destlen, "%s://%s/encounter/new/?type=%s&locationId=%u&userId=%u", protocol,
           host, eventType, locationId, userId);
}

void initMFRC522(MFRC522* mfrc522, MFRC522::MIFARE_Key* key) {
  const char* mname = "initMFRC522";
  Serial.printf("%s: begin\n", mname);
  const int RST_PIN = 5;  // Configurable, see typical pin layout above
  const int SS_PIN = 15;  // Configurable, see typical pin layout above
  *mfrc522 = MFRC522(SS_PIN, RST_PIN);
  SPI.begin();                         // Init SPI bus
  mfrc522->PCD_Init();                 // Init MFRC522
  mfrc522->PCD_DumpVersionToSerial();  // Show details of PCD - MFRC522 Card
                                       // Reader details
  Serial.println(F("Scan PICC to see UID, SAK, type, and data blocks..."));

  // Prepare the key (used both as key A and as key B)
  // using FFFFFFFFFFFFh which is the default at chip delivery from the factory
  memset(key->keyByte, 0xFF, 6);
  Serial.printf("%s: complete\n", mname);
}

uint32_t httpGet(char* url) {
  char* mname = "httpGet";
  HTTPClient http;            // instantiate httpclient
  http.begin(url);            // specify request destination
  int httpCode = http.GET();  // send request
  Serial.printf("%s: sending HTTP GET request to url: %s\n", mname, url);
  if (httpCode > 0)  // check returning code
  {
    Serial.printf("%s: HTTP GET succeeded, response:\n", mname,
                  http.getString().c_str());
  } else {
    Serial.printf("%s: HTTP GET failed, error: %s\n",
                  http.errorToString(httpCode).c_str());
  }
  http.end();  // close connection
  return ERR_OK;
}

uint32_t wpaConnect(const char* ssid, const char* password) {
  char* mname = "wpaConnect";
  Serial.printf("%s: begin\n", mname);
  WiFi.begin(ssid, password);
  while (true) {
    if (WiFi.status() == WL_CONNECTED) {
      Serial.printf("%s: connection succeeded\n", mname);
      Serial.printf("%s: current ip address: %s\n", mname,
                    WiFi.localIP().toString().c_str());
      break;
    } else {
      Serial.printf("%s: connection attempt failed, retrying\n", mname);
      delay(500);
    }
  }
  Serial.printf("%s: complete\n", mname);
  return ERR_OK;
}

uint32_t enterpriseWpaConnect(const char* ssid, const char* username,
                              const char* password) {
  char* mname = "enterpriseWpaConnect";

  wifi_set_opmode(STATION_MODE);
  Serial.printf("%s: begin\n", mname);

  struct station_config wifi_config = {0};
  strcpy((char*)wifi_config.ssid, ssid);
  int err;
  if (!wifi_station_set_config(&wifi_config) != 0) {
    Serial.printf("%s: wifi_station_set_config failed\n", mname);
  }
  wifi_station_clear_cert_key();
  wifi_station_clear_enterprise_ca_cert();
  if (!wifi_station_set_wpa2_enterprise_auth(1)) {
    Serial.printf("%s: wifi_station_set_wpa2_enterprise_auth failed\n", mname);
  }
  if (!wifi_station_set_enterprise_username((u8*)username, strlen(username))) {
    Serial.printf("%s: wifi_station_set_enterprise_username failed\n", mname);
  }
  if (!wifi_station_set_enterprise_identity((u8*)username, strlen(username))) {
    Serial.printf("%s: wifi_station_set_enterprise_identity failed\n", mname);
  }
  if (!wifi_station_set_enterprise_password((u8*)password, strlen(password))) {
    Serial.printf("%s: wifi_station_set_enterprise_password failed\n", mname);
  }
  if (!wifi_station_connect()) {
    Serial.printf("%s:  wifi_station_connect failed\n", mname);
  }
  Serial.printf("%s: complete\n", mname);
  return ERR_OK;
}

void to_uint32_t(uint32_t* dest, uint8_t* src) {
  *dest = (src[0] << 24) + (src[1] << 16) + (src[2] << 8) + src[3];
}

void to_uint8_t_ptr(uint8_t* dest, uint32_t* src) {
  dest[0] = (*src >> 24) & 0xFF;
  dest[1] = (*src >> 16) & 0xFF;
  dest[2] = (*src >> 8) & 0xFF;
  dest[3] = (*src >> 0) & 0xFF;
}
