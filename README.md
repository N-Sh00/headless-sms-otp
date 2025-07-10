# SMS-OTP Keycloak Provider

A Keycloak extension that adds SMS-based one-time-password (OTP) authentication via the [sms.ir](https://sms.ir) service.  
It provides both:
- A **Browser/Direct-Grant authenticator** (`SMS OTP (phone)`) you can add to any Keycloak authentication flow.
- A **JSON REST façade** under `/sms` to drive login from mobile/native apps without a WebView.

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Getting Started](#getting-started)
5. [Configuration](#configuration)
6. [Building & Packaging](#building--packaging)
7. [Running with Docker Compose](#running-with-docker-compose)
8. [Manual Deployment](#manual-deployment)
9. [Usage](#usage)
    - [Browser Flow](#browser-flow)
    - [JSON API (Mobile)](#json-api-mobile)
10. [Configuration Properties](#configuration-properties)
11. [Project Structure](#project-structure)
12. [Customization](#customization)

---

## Features

- **Phone-number login**: Users can sign in with just their phone number.
- **Auto-user creation**: If the phone isn’t already a user, one is created on the fly.
- **PKCE + OAuth2 code**: Mobile clients get a proper OAuth2 code grant.
- **Pluggable SMS SPI**: Default `sms-ir` sender; swap in any other via SPI.

---

## Architecture

[ Keycloak ]
├─ Authenticator SPI
│ └─ SmsOtpAuthenticator (browser / direct-grant)
├─ RealmResourceProvider SPI
│ └─ /sms/init, /sms/confirm, /sms/ping
└─ Provider SPI “sms-sender”
└─ SmsIrSenderProvider → sms.ir REST API

---

## Prerequisites

- Java 21 (for compilation)
- Maven 3.6+
- Docker & Docker Compose (optional but recommended)
- A valid **sms.ir** account with API key & template ID

---

## Getting Started

```bash
# Clone the repository
git clone https://github.com/your-org/sms-otp-kc-provider.git
cd sms-otp-kc-provider
```

---

## Configuration

1. Environment Variables
```bash
export SMSIR_API_KEY="your-smsir-api-key"
export SMSIR_TEMPLATE_ID="your-template-id"
export SMSIR_LINE_NUMBER="your-line-number"    # optional for some endpoints
```

2. Keycloak SPI config (in kc.conf or via CLI args):
```properties
spi-sms-sender-sms-ir-apiKey=${SMSIR_API_KEY}
spi-sms-sender-sms-ir-templateId=${SMSIR_TEMPLATE_ID}
spi-sms-sender-sms-ir-lineNumber=${SMSIR_LINE_NUMBER}
spi-sms-sender-provider=sms-ir
```

---

## Building & Packaging

```bash
mvn clean package
# → produces:
#    target/sms-otp-kc-provider-0.0.1-SNAPSHOT.jar
#    target/sms-otp-kc-provider-0.0.1-SNAPSHOT-kc-provider.jar
```

---

## Running with Docker Compose
A PostgreSQL + Keycloak stack is provided:

```yaml
# docker-compose.yml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_DB:   keycloak
      POSTGRES_USER: kcuser
      POSTGRES_PASSWORD: kcpass
    volumes:
      - kc_db_data:/var/lib/postgresql/data

  keycloak:
    build:
      context: .
      dockerfile: docker/Dockerfile
    depends_on:
      - db
    environment:
      KC_DB:               postgres
      KC_DB_URL:           jdbc:postgresql://db:5432/keycloak
      KC_DB_USERNAME:      kcuser
      KC_DB_PASSWORD:      kcpass
      KC_HTTP_ENABLED:     "true"
      KEYCLOAK_ADMIN:      admin
      KEYCLOAK_ADMIN_PASSWORD: admin
      SMSIR_API_KEY:       "${SMSIR_API_KEY}"
      SMSIR_TEMPLATE_ID:   "${SMSIR_TEMPLATE_ID}"
      SMSIR_LINE_NUMBER:   "${SMSIR_LINE_NUMBER}"
      KC_LOG_LEVEL:        DEBUG
    ports:
      - "8080:8080"
volumes:
  kc_db_data:
```

```bash
# Start the stack
docker-compose up --build
```
Keycloak will be available at http://localhost:8080.

---

## Manual Deployment
If you already have a running Keycloak instance:

1. Copy the shaded JAR
```bash
cp target/*kc-provider.jar /path/to/keycloak/providers/
```

2. Add kc.conf under /opt/keycloak/conf/ (or pass CLI args).

3. Restart Keycloak:

---

## Usage
### Browser Flow

1. In the Admin Console, go to Authentication → Flows.
2. Clone an existing flow (e.g. “Browser”).
3. Add execution: select SMS OTP (phone), requirement REQUIRED.
4. Arrange it after Username Password Form (or in place of it).
5. Users will see a form asking for phone_number, then otp.

### JSON API (Mobile)
Three endpoints under /realms/{realm}/sms:

* POST `/sms/init`
```json
{ "phone_number": "09123456789",
  "client_id":   "my-app",
  "code_challenge": "<PKCE challenge>",
  "state":       "xyz",
  "redirect_uri":"com.example.app://callback" }
```
→ returns `{ "txn": "<transaction-ID>" }`

* POST `/sms/confirm`
```json
{ "phone_number": "09123456789",
  "otp":         "123456",
  "txn":         "<transaction-ID>" }
```
→ returns `{ "code": "<auth-code>", "state":"xyz" }`

* GET `/sms/ping`
  → returns `{ "msg": "pong" }`

---

## Configuration Properties

| Env var                   | Description                    | Default / Required  |
|---------------------------|--------------------------------|---------------------|
| `SMSIR_API_KEY`           | Your sms.ir API key            | **Required**        |
| `SMSIR_TEMPLATE_ID`       | sms.ir template ID (numeric)   | **Required**        |
| `SMSIR_LINE_NUMBER`       | sms.ir line number (if needed) | Optional            |
| `KC_DB_URL`               | JDBC URL for Keycloak database | Required            |
| `KEYCLOAK_ADMIN`          | Admin username                 | Defaults to `admin` |
| `KEYCLOAK_ADMIN_PASSWORD` | Admin password                 | Defaults to `admin` |

---

## Project Structure

```text
src/
├─ main/java/com/example/keycloak/
│   ├─ auth/           SmsOtpAuthenticator & Factory
│   ├─ ext/            REST endpoints & session helper
│   └─ provider/       SMS sender SPI & sms-ir implementation
└─ resources/META-INF/services/   SPI registrations
docker/
├─ kc.conf
└─ Dockerfile
pom.xml
docker-compose.yml
```

---

## Customization
- **OTP TTL:** currently 120s `(OtpAuthenticator.OTP_TTL_SECONDS)`
- **OTP length:** 6 digits `(OTP_LENGTH)`
- **Swap SMS SPI:** implement `SmsSenderProvider`, register via SPI

---

