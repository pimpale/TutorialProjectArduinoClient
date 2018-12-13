#include <string.h>

#include <SPI.h>
#include <MFRC522.h>
#include <ESP8266HTTPClient.h> 

#include <user_interface.h>
#include <wpa2_enterprise.h>


/************************* WiFi Access Point *********************************/


static const char* ssid = "ESUHSD";
static const char* username = "usernamegoeshere";
static const char* password = "passwordgoeshere";

static const uint64_t locationId = 1;

static const int BAUD = 9600;


MFRC522 mfrc522;  // Create MFRC522 instance
MFRC522::MIFARE_Key key;

void setup() {
	Serial.begin(BAUD);   // Initialize serial communications with the PC
	while (!Serial);    // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
	Serial.printf("setup: complete\n");

	initMFRC522(&mfrc522, &key);
	wpaConnect("ESUHSD", "pimpalegovind4614", "help me");

	Serial.printf("setup: complete\n");


}

void loop() {
	// In this sample we use the second sector,
	// that is: sector #1, covering block #4 up to and including block #7
	char sector         = 1;
	char blockAddr      = 4;
	MFRC522::StatusCode status;
	char buffer[18];
	char size = sizeof(buffer);


	// Look for new cards
	if ( ! mfrc522.PICC_IsNewCardPresent()) {
		return;
	}

	// Select one of the cards
	if ( ! mfrc522.PICC_ReadCardSerial()) {
		return;
	}
	Serial.println(F("Authenticating using key A..."));
	status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockAddr, &key, &(mfrc522.uid));
	if (status != MFRC522::STATUS_OK) {
		Serial.print(F("PCD_Authenticate() failed: "));
		Serial.println(mfrc522.GetStatusCodeName(status));
		return;
	}

	// Read data from the block
	Serial.print(F("Reading data from block ")); Serial.print(blockAddr);
	Serial.println(F(" ..."));
	status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, (byte*)buffer, (byte*)&size);
	if (status != MFRC522::STATUS_OK) {
		Serial.print(F("MIFARE_Read() failed: "));
		Serial.println(mfrc522.GetStatusCodeName(status));
	}
	Serial.print(F("Data in block ")); Serial.print(blockAddr,HEX); Serial.println(F(":"));
	dump_char_array(buffer, 4); Serial.println();
	Serial.println();

	uint64_t studentId = (buffer[0] << 24) + (buffer[1] << 16) + (buffer[2] << 8) + buffer[3];

	Serial.printf("The student ID number is: %ld \n",(unsigned long)studentId);
	char url[256];
	sprintf(url,"http://192.168.1.96/events/new/?locationId=%ld&studentId=%ld", (unsigned long) locationId, (unsigned long) studentId);
	httpGet("http://google.com");

	mfrc522.PICC_HaltA();
	mfrc522.PCD_StopCrypto1();
	// Dump debug info about the card; PICC_HaltA() is automatically called
	//mfrc522.PICC_DumpToSerial(&(mfrc522.uid));
}

void initMFRC522(MFRC522* mfrc522, MFRC522::MIFARE_Key* key)
{
	const char* mname = "initMFRC522";
	Serial.printf("%s: begin\n",mname);
	const int RST_PIN = 5;          // Configurable, see typical pin layout above
	const int SS_PIN = 15;          // Configurable, see typical pin layout above
	*mfrc522 = MFRC522(SS_PIN, RST_PIN);
	SPI.begin();      // Init SPI bus
	mfrc522->PCD_Init();   // Init MFRC522
	mfrc522->PCD_DumpVersionToSerial();  // Show details of PCD - MFRC522 Card Reader details
	Serial.println(F("Scan PICC to see UID, SAK, type, and data blocks..."));

	// Prepare the key (used both as key A and as key B)
	// using FFFFFFFFFFFFh which is the default at chip delivery from the factory
	memset(key->keyByte, 0xFF, 6); 
	Serial.printf("%s: complete\n",mname);
}



void httpGet(char* url)
{
	char* mname = "httpGet";
	HTTPClient http; //instantiate httpclient
	http.begin(url); //specify request destination
	int httpCode = http.GET(); //send request
	Serial.printf("%s: sending HTTP GET request to url: %s\n",mname, url);
	if(httpCode>0) //check returning code
	{
		Serial.printf("%s: HTTP GET succeeded, response:\n",mname, http.getString().c_str());
	}
	else 
	{
		Serial.printf("%s: HTTP GET failed, error: %s\n", http.errorToString(httpCode).c_str());
	}
	http.end();//close connection
}

void wpaConnect(const char* SSID, const char* username, const char* password)
{
	char* mname = "wpaConnect";
 
	wifi_set_opmode(STATION_MODE);
	Serial.printf("%s: begin\n", mname);
  
	struct station_config wifi_config = { 0 };
	strcpy((char*)wifi_config.ssid, ssid);
  int err;
	if(!wifi_station_set_config(&wifi_config) != 0)
	{
		Serial.printf("%s: wifi_station_set_config failed\n", mname);
	}
	wifi_station_clear_cert_key();
	wifi_station_clear_enterprise_ca_cert();
	if(!wifi_station_set_wpa2_enterprise_auth(1))
	{
		Serial.printf("%s: wifi_station_set_wpa2_enterprise_auth failed\n", mname);
	}
	if(!wifi_station_set_enterprise_username((u8*)username, strlen(username)))
	{
		Serial.printf("%s: wifi_station_set_enterprise_username failed\n", mname);
	}
	if(!wifi_station_set_enterprise_identity((u8*)username, strlen(username)))
	{
		Serial.printf("%s: wifi_station_set_enterprise_identity failed\n", mname);
	}
	if(!wifi_station_set_enterprise_password((u8*)password, strlen(password)))
	{
		Serial.printf("%s: wifi_station_set_enterprise_password failed\n", mname);
	}
	if(!wifi_station_connect())
	{
		Serial.printf("%s:  wifi_station_connect failed\n", mname);
	}
	Serial.printf("%s: complete\n", mname);
}

void dump_char_array(char *buffer, char bufferSize) {
	for (char i = 0; i < bufferSize; i++) {
		Serial.print(buffer[i] < 0x10 ? " 0" : " ");
		Serial.print(buffer[i], HEX);
	}
}


