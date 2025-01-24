#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <RTClib.h>
#include <Keypad.h>
#include <TinyGPS++.h>
#include <Adafruit_Fingerprint.h>
#include <MFRC522.h>
#include "SD.h"
#include "SPI.h"

// Definizioni dei pin
#define RST_PIN 5
#define SS_PIN 53
#define GPS_SERIAL Serial2
#define SD_CS 4
#define SerialFP Serial1

// Oggetti
TinyGPSPlus gps;
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&Serial1, 0);
RTC_DS1307 rtc;
MFRC522 mfrc522(SS_PIN, RST_PIN);
LiquidCrystal_I2C lcd(0x27, 20, 4);

// Impostazioni keypad
const byte ROW_NUM = 4;
const byte COLUMN_NUM = 4;
char keys[ROW_NUM][COLUMN_NUM] = {
    {'1', '2', '3', 'A'},
    {'4', '5', '6', 'B'},
    {'7', '8', '9', 'C'},
    {'*', '0', '#', 'D'}
};
byte pin_rows[ROW_NUM] = {22, 23, 24, 25};
byte pin_column[COLUMN_NUM] = {26, 27, 28, 29};
Keypad keypad = Keypad(makeKeymap(keys), pin_rows, pin_column, ROW_NUM, COLUMN_NUM);

// Variabili
String currentTime = "2024/12/10 15:30:45";
int state = 1;
String IPAddress = "192.168.1.100";
String commessa = "";
int operazione = 0;
String codiceDaScrivere = "";
int statoPrecedente = -1;
String codiceLetto = "";
String commessaPrecedente = "";
const byte block = 4;
MFRC522::StatusCode status;
MFRC522::MIFARE_Key keyA = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const size_t bufferSize = 512;


uint8_t downloadFingerprintTemplate(uint8_t fingerTemplateAppo[bufferSize], uint16_t id) {
    Serial.println("------------------------------------");
    Serial.print("Tentativo di caricare l'impronta con ID #");
    Serial.println(id);

    uint8_t p = finger.loadModel(id);
    if (p == FINGERPRINT_OK) {
        Serial.print("Modello ID ");
        Serial.print(id);
        Serial.println(" caricato con successo.");
    } else {
        Serial.print("Errore nel caricamento del modello ID ");
        Serial.println(id);
        return p;
    }

    Serial.print("Tentativo di ottenere i dati del modello per l'ID #");
    Serial.println(id);
    p = finger.getModel();
    if (p == FINGERPRINT_OK) {
        Serial.print("Trasferimento del modello ID ");
        Serial.print(id);
        Serial.println(" in corso...");
    } else {
        Serial.print("Errore sconosciuto: ");
        Serial.println(p);
        return p;
    }

    uint8_t bytesReceived[534];
    memset(bytesReceived, 0xff, 534);
    uint32_t starttime = millis();
    int i = 0;
    while (i < 534 && (millis() - starttime) < 20000) {
        if (SerialFP.available()) {
            bytesReceived[i++] = SerialFP.read();
        }
    }

    Serial.print(i);
    Serial.println(" byte letti.");
    Serial.println("Decodifica del pacchetto...");

    memset(fingerTemplateAppo, 0xff, bufferSize);
    int uindx = 9, index = 0;
    memcpy(fingerTemplateAppo + index, bytesReceived + uindx, 256);
    uindx += 256;
    uindx += 2;
    uindx += 9;
    index += 256;
    memcpy(fingerTemplateAppo + index, bytesReceived + uindx, 256);

    Serial.println("Modello acquisito con successo.");
    return p;
}

void write_template_To_R307(uint8_t fingerTemplate[512], int id) {
    if (!finger.write_template_to_sensor(512, fingerTemplate)) {
        Serial.println("Errore nella scrittura sul sensore: controllare la connessione o la validità del modello.");
        return;
    }
    if (finger.storeModel(id) == FINGERPRINT_OK) {
        Serial.print("Template salvato correttamente:");
        Serial.println(id);
    } else {
        Serial.println("Errore durante il salvataggio del modello.");
    }
}

void write_template_from_NFC() {
    uint8_t fingerTemplate[512];
    uint8_t IDGeneral = 0;
    uint8_t blockData[16];

    for (uint8_t PrintID = 1; PrintID <= 4; PrintID++) {
        for (uint8_t SectorID = 0; SectorID < 32; SectorID++) {
            readBlock(updateBlock(IDGeneral), blockData);
            memcpy(fingerTemplate + (SectorID * 16), blockData, 16);
            ++IDGeneral;
        }
        write_template_To_R307(fingerTemplate, PrintID);
    }
}

bool readBlock(byte blockAddr, byte *blockData) {
    byte length = 18;
    status = mfrc522.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A,
        blockAddr,
        &keyA,
        &(mfrc522.uid)
    );
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Autenticazione del blocco non riuscita: "));
        Serial.println(blockAddr);
        Serial.println(mfrc522.GetStatusCodeName(status));
        return false;
    }

    status = mfrc522.MIFARE_Read(blockAddr, blockData, &length);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("Errore durante la lettura del blocco: "));
        Serial.println(blockAddr);
        Serial.println(mfrc522.GetStatusCodeName(status));
        return false;
    }
    return true;
}

bool scriviPacchetto(byte buffer[16], int block) {
    if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &keyA, &(mfrc522.uid)) != MFRC522::STATUS_OK) {
        Serial.println("Autenticazione fallita.");
        return false;
    }

    if (mfrc522.MIFARE_Write(block, buffer, 16) != MFRC522::STATUS_OK) {
        Serial.println("Scrittura fallita.");
        return false;
    }
    return true;
}

bool backup_NFC() {
    uint8_t fingerTemplateArray[512];
    byte blockAdd = 0;

    for (int fingerID = 1; fingerID <= 4; fingerID++) {
        if (finger.loadModel(fingerID) == FINGERPRINT_OK) {
            if (downloadFingerprintTemplate(fingerTemplateArray, fingerID) == FINGERPRINT_OK) {
                // Success
            } else {
                memset(fingerTemplateArray, 0xFF, 512);
                Serial.println("Modello vuoto salvato nel buffer per NFC");
            }
        } else {
            memset(fingerTemplateArray, 0xFF, 512);
            Serial.println("Nessun modello trovato, buffer riempito con 0xFF");
        }

        uint8_t destinationArray[16];
        for (size_t i = 0; i < 32; i++) {
            memcpy(destinationArray, fingerTemplateArray + (i * 16), 16);
            if (scriviPacchetto(destinationArray, updateBlock(blockAdd))) {
                ++blockAdd;
            } else {
                Serial.println("Errore scrittura su scheda NFC");
                return false;
            }
        }
    }

    Serial.println("Trasferimento su scheda NFC eseguito con successo");
    return true;
}

byte updateBlock(byte blockToWrite) {
    static const int values[] = {
        5, 6, 8, 9, 10, 12, 13, 14, 16, 17, 18, 20, 21, 22, 24,
        25, 26, 28, 29, 30, 32, 33, 34, 36, 37, 38, 40, 41, 42,
        44, 45, 46, 48, 49, 50, 52, 53, 54, 56, 57, 58, 60, 61,
        62, 64, 65, 66, 68, 69, 70, 72, 73, 74, 76, 77, 78, 80,
        81, 82, 84, 85, 86, 88, 89, 90, 92, 93, 94, 96, 97, 98,
        100, 101, 102, 104, 105, 106, 108, 109, 110, 112, 113, 114,
        116, 117, 118, 120, 121, 122, 124, 125, 126, 128, 129, 130, 131,
        132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 144,
        145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156,
        157, 158, 160, 161, 162, 163, 164, 165
    };
    
    if (blockToWrite >= 0 && blockToWrite < sizeof(values) / sizeof(values[0])) {
        return values[blockToWrite];
    } else {
        return -1;
    }
}

int findFirstAvailableID() {
    int id = 1;
    
    while (id <= 127) {
        if (finger.loadModel(id) != FINGERPRINT_OK) {
            return id;
        }
        id++;
    }
    
    return -1;
}

void add_fingerPrintToSensor() {
    Serial.println("Pronto per registrare un'impronta digitale!");
    Serial.println("Sto cercando il primo ID disponibile...");
    
    int id = findFirstAvailableID();
    
    if (id == -1) {
        Serial.println("Nessun ID disponibile trovato, memoria piena!");
        return;
    }
    
    Serial.print("Registrazione per l'ID #");
    Serial.println(id);
    Serial.print("In attesa di un dito valido per registrarlo come ID: ");
    Serial.println(id);
    
    while (finger.getImage() != FINGERPRINT_OK) {
    }
    
    Serial.println("Immagine acquisita");
    
    if (finger.image2Tz(1) == FINGERPRINT_OK) {
        Serial.println("Immagine convertita con successo");
    } else {
        Serial.println("Errore nella conversione dell'immagine");
        return;
    }
    
    Serial.println("Rimuovi il dito");
    delay(2000);
    
    uint8_t p = 0;
    while (p != FINGERPRINT_NOFINGER) {
        p = finger.getImage();
    }
    
    Serial.println("Posiziona nuovamente lo stesso dito, in attesa...");
    
    while (finger.getImage() != FINGERPRINT_OK) {
    }
    
    Serial.println("Immagine acquisita");
    
    if (finger.image2Tz(2) == FINGERPRINT_OK) {
        Serial.println("Immagine convertita con successo");
    } else {
        Serial.println("Errore nella conversione dell'immagine");
        return;
    }
    
    Serial.print("Creazione del modello per l'ID #");
    Serial.println(id);
    
    if (finger.createModel() == FINGERPRINT_OK) {
        Serial.println("Le impronte corrispondono!");
        Serial.println("Modello creato con successo");
    } else {
        Serial.println("Errore nella creazione del modello");
        return;
    }
    
    Serial.print("Salvataggio del modello sul sensore...");
    
    if (finger.storeModel(id) == FINGERPRINT_OK) {
        Serial.println("Modello salvato con successo!");
    } else {
        Serial.println("Errore durante il salvataggio del modello sul sensore");
    }
}

void clean_sensor() {
    Serial.println("Sto cancellando la memoria del sensore...");
    
    if (finger.emptyDatabase() == FINGERPRINT_OK) {
        Serial.println("Memoria cancellata con successo!");
    } else {
        Serial.println("Errore durante la cancellazione della memoria.");
    }
}

void printHex(int num, int precision) {
    char tmp[16];
    char format[128];
    
    sprintf(format, "%%.%dX", precision);
    sprintf(tmp, format, num);
    Serial.print(tmp);
}

void verify_fingerprint() {
    if (finger.getImage() == FINGERPRINT_OK) {
        Serial.println("Immagine acquisita");
        
        if (finger.image2Tz() != FINGERPRINT_OK) {
            Serial.println("Errore nella conversione dell'immagine");
            return;
        }
        
        if (finger.fingerFastSearch() == FINGERPRINT_OK) {
            Serial.print("Impronta corrispondente trovata! ID #");
            Serial.print(finger.fingerID);
            Serial.print(" con livello di confidenza ");
            Serial.println(finger.confidence);
            state = 3;
        } else {
            Serial.println("Nessuna corrispondenza trovata");
        }
    }
}

void aggiornaDisplay() {
    lcd.clear();
    switch (state) {
        case 0: mostraReset(); break;
        case 1: mostraAttesaCarta(); break;
        case 2: mostraNuovaTessera(); break;
        case 3: mostraAttesaIngressoUscita(); break;
        case 4: mostraCommessa(); break;
        case 5: mostraUscita(); break;
        case 6: mostraIngresso(); break;
        case 12: mostraAttesaImprontaPerVerifica(); break;
        case 13: mostraAttesaCartaPerScrittura(); break;
        case 7: break;
        default: mostraErroreStato(); break;
    }
}

void mostraReset() {
    centraTesto("RESET", 1);
}

void mostraAttesaCarta() {
    centraTesto(currentTime, 0);
    centraTesto("ATTESA CARTA", 1);
    centraTesto("Avvicina tessera", 3);
}

void mostraAttesaCartaPerScrittura() {
    centraTesto(currentTime, 0);
    centraTesto("ATTESA CARTA", 1);
    centraTesto("PER INIZIALIZZAZIONE", 2);
    centraTesto("Avvicina tessera", 3);
}

void UpdateOnlyDateTime() {
    DateTime now = rtc.now();
    char buffer[20];
    sprintf(buffer, "%02d/%02d/%04d %02d:%02d:%02d",
            now.day(), now.month(), now.year(),
            now.hour(), now.minute(), now.second());
    lcd.setCursor(0, 0);
    lcd.print(buffer);
}

void UpdateOnlyCommessa() {
    lcd.setCursor(0, 2);
    lcd.print("Commessa: " + commessa);
}

void CleanCommessa() {
    lcd.setCursor(0, 2);
    lcd.print("Commessa:        ");
}

void mostraNuovaTessera() {
    centraTesto("NUOVA TESSERA", 0);
    lcd.setCursor(0, 2);
    lcd.print("Inserire una nuova");
    lcd.setCursor(0, 3);
    lcd.print("tessera per attiv.");
}

void mostraAttesaIngressoUscita() {
    centraTesto("DIPENDENTE: " + codiceLetto, 0);
    centraTesto("INSERIRE OPERAZIONE", 1);
    lcd.setCursor(0, 3);
    lcd.print("1: IN | 2: OUT");
}

void mostraAttesaImprontaPerVerifica() {
    centraTesto(currentTime, 0);
    centraTesto("ATTESA IMPRONTA", 1);
    centraTesto("Appoggiare il dito", 3);
}

void mostraCommessa() {
    centraTesto("DIPENDENTE: " + codiceLetto, 0);
    centraTesto("INSERIRE COMMESSA", 1);
    lcd.setCursor(0, 2);
    lcd.print("Commessa: " + commessa);
    lcd.setCursor(0, 3);
    lcd.print("*: Cancella commessa");
}

void mostraUscita() {
    centraTesto("USCITA", 1);
    lcd.setCursor(0, 3);
    lcd.print("Grazie!  " + codiceLetto);
}

void mostraIngresso() {
    centraTesto("INGRESSO", 1);
    lcd.setCursor(0, 3);
    lcd.print("Benvenuto!  " + codiceLetto);
}

void mostraErroreStato() {
    centraTesto("ERRORE STATO", 1);
}

void centraTesto(String testo, int riga) {
    int lunghezza = testo.length();
    int spazi = (20 - lunghezza) / 2;
    lcd.setCursor(0, riga);
    for (int i = 0; i < spazi; i++) lcd.print(" ");
    lcd.print(testo);
}

void setup() {
    // Inizializzazione delle comunicazioni
    Serial.begin(115200);
    SerialFP.begin(57600);
    GPS_SERIAL.begin(9600);
    
    // Inizializzazione delle periferiche
    SPI.begin();
    mfrc522.PCD_Init();
    lcd.init();
    lcd.backlight();
    lcd.clear();
    aggiornaDisplay();

    // Inizializzazione e controllo del modulo RTC
    if (!rtc.begin()) {
        Serial.println("Errore RTC");
        while (1);
    }

    if (!rtc.isrunning()) {
        rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
    }

    // Inizializzazione del sensore di impronte digitali
    if (finger.verifyPassword()) {
        Serial.println("Sensore di impronte digitali trovato!");
    } else {
        Serial.println("Sensore di impronte digitali non trovato :(");
        while (1);
    }

    // Inizializzazione della scheda SD
    if (!SD.begin(SD_CS)) {
        Serial.println("Errore nell'inizializzazione della scheda SD!");
        while (1);
    }
    
    Serial.println("Scheda SD inizializzata correttamente.");

    // Inizializzazione della chiave del lettore MFRC522
    for (byte i = 0; i < 6; i++) {
        keyA.keyByte[i] = 0xFF;
    }
}

void loop() {
    while (GPS_SERIAL.available() > 0) {
        char c = GPS_SERIAL.read();
        gps.encode(c);
    }

    unsigned long currentMillis = millis();

    if (state != statoPrecedente) {
        aggiornaDisplay();
        statoPrecedente = state;
    }

    if (state == 4) {
        if (commessa != commessaPrecedente) {
            UpdateOnlyCommessa();
            commessaPrecedente = commessa;
        }
    }

    if ((state == 1) || (state == 12)) {
        UpdateOnlyDateTime();
    }

    if (state == 13) {
        if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
            return;
        }
        if (backup_NFC()) {
            mfrc522.PICC_HaltA();
            mfrc522.PCD_StopCrypto1();
            state = 0;
            return;
        }
    }

    currentTime = getDataOra();
    char key = keypad.getKey();
    leggiSeriale();

    if (state == 0) {
        operazione = 0;
        commessa = "";
        codiceDaScrivere = "";
        codiceLetto = "";
        delay(500);
        state = 1;
    }

    if (state == 1) {
        if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
            return;
        }
        String uid = "UID: ";
        for (byte i = 0; i < mfrc522.uid.size; i++) {
            uid += String(mfrc522.uid.uidByte[i], HEX);
            uid += " ";
        }
        codiceLetto = leggiCodice();
        if (codiceLetto != "") {
            Serial.print(currentTime + " - " + "Nuovo codice dipendente: ");
            Serial.println(codiceLetto);
            clean_sensor();
            write_template_from_NFC();
            state = 12;
        } else {
            Serial.println("Errore nella lettura.");
        }
        mfrc522.PICC_HaltA();
        mfrc522.PCD_StopCrypto1();
    }

    if (state == 2) {
        if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
            return;
        }
        if (scriviCodice(codiceDaScrivere)) {
            Serial.println("Codice scritto con successo!");
            delay(2500);
            state = 0;
        } else {
            Serial.println("Errore nella scrittura.");
            delay(2500);
        }
        mfrc522.PICC_HaltA();
        mfrc522.PCD_StopCrypto1();
    }

    if (state == 12) {
        verify_fingerprint();
    }

    if (state == 13) {
        if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
            return;
        }
        if (backup_NFC()) {
            mfrc522.PICC_HaltA();
            mfrc522.PCD_StopCrypto1();
            state = 0;
        }
    }

    if (state == 3) {
        if (key) {
            if (key == '1') {
                operazione = 1;
                Serial.println(currentTime + " - " + "Operazione impostata: Ingresso");
            } else if (key == '2') {
                operazione = 2;
                Serial.println(currentTime + " - " + "Operazione impostata: Uscita");
            } else if (key == '*') {
                operazione = 0;
                Serial.println("Operazione resettata");
            }
        }
        if (operazione == 1) {
            state = 4;
            key = 0;
        }
        if (operazione == 2) {
            state = 5;
            key = 0;
        }
    }

    if (state == 4) {
        if (key) {
            if (commessa.length() == 0) {
                if (key == 'A' || key == 'E') {
                    commessa += key;
                    Serial.println(currentTime + " - " + "Commessa aggiornata: " + commessa);
                } else {
                    Serial.println(currentTime + " - " + "Errore: Il primo carattere deve essere 'A' o 'E'");
                }
            } else {
                if (key >= '0' && key <= '9') {
                    if (commessa.length() < 7) {
                        commessa += key;
                        Serial.println(currentTime + " - " + "Commessa aggiornata: " + commessa);
                    } else {
                        Serial.println("Errore: Numero massimo di caratteri raggiunto");
                    }
                } else if (key == '*') {
                    commessa = "";
                    CleanCommessa();
                    Serial.println(currentTime + " - " + "Commessa cancellata dall'utente");
                } else {
                    Serial.println(currentTime + " - " + "Errore: Carattere non valido");
                }
            }
        }
        if (commessa.length() == 7) {
            state = 6;
        }
    }

    if (state == 5) {
        Serial.println(currentTime + " - " + "Uscita dipendente: " + codiceLetto);
        aggiornaDisplay();
        delay(2500);
        state = 0;
    }

    if (state == 6) {
        Serial.println(currentTime + " - " + "Ingresso dipendente: " + codiceLetto + "  commessa: " + commessa);
        aggiornaDisplay();
        delay(2500);
        state = 0;
    }
}

String getDataOra() {
    DateTime now = rtc.now();
    char dataOra[20];
    snprintf(dataOra, sizeof(dataOra), "%02d/%02d/%04d %02d:%02d:%02d",
             now.day(), now.month(), now.year(),
             now.hour(), now.minute(), now.second());
    return String(dataOra);
}

void mostraDatiGPS() {
    if (gps.location.isUpdated() || gps.date.isUpdated() || gps.time.isUpdated()) {
        float latitude = gps.location.lat();
        float longitude = gps.location.lng();
        int day = gps.date.day();
        int month = gps.date.month();
        int year = gps.date.year();
        int hour = gps.time.hour();
        int minute = gps.time.minute();
        int second = gps.time.second();
        Serial.println("----- Dati GPS -----");
        Serial.print("Latitudine: ");
        Serial.println(latitude, 6);
        Serial.print("Longitudine: ");
        Serial.println(longitude, 6);
        Serial.print("Data: ");
        Serial.print(day);
        Serial.print("/");
        Serial.print(month);
        Serial.print("/");
        Serial.println(year);
        Serial.print("Ora (UTC): ");
        Serial.print(hour);
        Serial.print(":");
        Serial.print(minute);
        Serial.print(":");
        Serial.println(second);
        Serial.println("--------------------");
    } else {
        Serial.println("Nessun nuovo dato GPS ricevuto.");
    }
}

bool scriviCodice(String codice) {
    if (codice.length() > 16) {
        Serial.println("Errore: il codice è troppo lungo.");
        return false;
    }
    byte buffer[16];
    codice.getBytes(buffer, 16);
    if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &keyA, &(mfrc522.uid)) != MFRC522::STATUS_OK) {
        Serial.println("Autenticazione fallita.");
        return false;
    }
    if (mfrc522.MIFARE_Write(block, buffer, 16) != MFRC522::STATUS_OK) {
        Serial.println("Scrittura fallita.");
        return false;
    }
    return true;
}

String leggiCodice() {
    byte buffer[18];
    byte bufferSize = sizeof(buffer);
    if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &keyA, &(mfrc522.uid)) != MFRC522::STATUS_OK) {
        Serial.println("Autenticazione fallita.");
        return "";
    }
    if (mfrc522.MIFARE_Read(block, buffer, &bufferSize) != MFRC522::STATUS_OK) {
        Serial.println("Lettura fallita.");
        return "";
    }
    String codice = "";
    for (byte i = 0; i < 5; i++) {
        if (buffer[i] == 0) break;
        codice += (char)buffer[i];
    }
    return codice;
}

bool impostaRTC(String dataOra) {
    int anno, mese, giorno, ora, minuto, secondo;
    if (sscanf(dataOra.c_str(), "%d/%d/%d %d:%d:%d", &anno, &mese, &giorno, &ora, &minuto, &secondo) == 6) {
        rtc.adjust(DateTime(anno, mese, giorno, ora, minuto, secondo));
        return true;
    }
    return false;
}

void leggiSeriale() {
    if (Serial.available() > 0) {
        String comando = Serial.readStringUntil('\n');
        comando.trim();
        if (comando.startsWith("GET ")) {
            if (comando == "GET DATETIME") {
                Serial.println("DATETIME: " + currentTime);
            } else if (comando == "GET STATE") {
                Serial.println("STATE: " + String(state));
            } else if (comando == "GET GPS") {
                mostraDatiGPS();
            } else if (comando == "GET CMDS") {
                Serial.println("Comandi disponibili:");
                Serial.println("GET DATETIME - Restituisce la data e l'ora correnti.");
                Serial.println("GET STATE - Restituisce lo stato corrente del dispositivo.");
                Serial.println("GET GPS - Restituisce i dati letti dal GPS.");
                Serial.println("SET DATETIME [value] - Imposta la data e l'ora.");
                Serial.println("SET STATE [value] - Imposta lo stato del dispositivo.");
                Serial.println("SET COMMESSA [value] - Imposta la commessa (7 caratteri alfanumerici).");
                Serial.println("SET OPERAZIONE [value] - Imposta l'operazione (0, 1 o 2).");
                Serial.println("SET NEWCODE [value] - Imposta il codice (5 cifre).");
                Serial.println("SET RESET - Resetta lo stato del dispositivo.");
                Serial.println("CMD FP_ADD - Aggiungi impronta a sensore R307.");
                Serial.println("CMD FP_BACKUP - Esegui il backup nella NFC.");
                Serial.println("CMD FP_CLEAN - Svuota le impronte del sensore.");
                Serial.println("CMD FP_VERIFY - Verifica il fingerprint.");
            } else {
                Serial.println("ERRORE: Comando GET non valido.");
            }
        } else if (comando.startsWith("SET ")) {
            int primoSpazio = comando.indexOf(' ');
            int secondoSpazio = comando.indexOf(' ', primoSpazio + 1);
            if (secondoSpazio == -1) {
                Serial.println("ERRORE: Formato comando SET non valido.");
                return;
            }
            String tipo = comando.substring(primoSpazio + 1, secondoSpazio);
            String valore = comando.substring(secondoSpazio + 1);
            if (tipo == "DATETIME") {
                if (impostaRTC(valore)) {
                    currentTime = valore;
                    Serial.println("DATETIME aggiornato a: " + valore);
                } else {
                    Serial.println("ERRORE: Formato DATETIME non valido.");
                }
            } else if (tipo == "STATE") {
                int nuovoState = valore.toInt();
                if (nuovoState >= 0) {
                    state = nuovoState;
                    Serial.println("STATE aggiornato a: " + String(state));
                } else {
                    Serial.println("ERRORE: Valore STATE non valido.");
                }
            } else if (tipo == "DISPLAY") {
                int nuovoState = valore.toInt();
                if (nuovoState >= 0) {
                    state = nuovoState;
                    Serial.println("STATE aggiornato a: " + String(state));
                } else {
                    Serial.println("ERRORE: Valore STATE non valido.");
                }
            } else if (tipo == "COMMESSA") {
                if (valore.length() == 7) {
                    commessa = valore;
                    Serial.println("COMMESSA aggiornata a: " + commessa);
                } else {
                    Serial.println("ERRORE: COMMESSA deve essere di 7 caratteri alfanumerici.");
                }
            } else if (tipo == "OPERAZIONE") {
                int nuovaOperazione = valore.toInt();
                if (nuovaOperazione >= 0 && nuovaOperazione <= 2) {
                    operazione = nuovaOperazione;
                    Serial.println("OPERAZIONE aggiornata a: " + String(operazione));
                } else {
                    Serial.println("ERRORE: OPERAZIONE deve essere un valore tra 0 e 2.");
                }
            } else if (tipo == "NEWCODE") {
                if (valore.length() == 5) {
                    codiceDaScrivere = valore;
                    state = 2;
                    Serial.println("NEWCODE aggiornato a: " + codiceDaScrivere);
                } else {
                    Serial.println("ERRORE: NEWCODE deve essere esattamente 5 cifre.");
                }
            } else if (tipo == "RESET") {
                Serial.println("RESET ricevuto da seriale");
                state = 0;
            } else {
                Serial.println("ERRORE: Tipo SET non riconosciuto.");
            }
        } else if (comando.startsWith("CMD ")) {
            String command = comando.substring(4);
            if (command.equals("FP_RESTORE")) {
            } else if (command.equals("FP_ADD")) {
                add_fingerPrintToSensor();
            } else if (command.equals("FP_BACKUP")) {
                state = 13;
            } else if (command.equals("FP_CLEAN")) {
                clean_sensor();
            } else if (command.equals("FP_VERIFY")) {
                verify_fingerprint();
            } else if (command.equals("FP_DELFILE")) {
            } else {
                Serial.println("ERRORE: Comando CMD non valido.");
            }
        } else {
            Serial.println("ERRORE: Comando non valido.");
        }
    }
}
