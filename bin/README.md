# Image Proxy / URL Encrypt Application

A Spring Boot application packaged as a WAR file that fetches documents from an external Laserfiche API and streams them to the client.

## Features

- **Proxy API**: Fetches documents from a configurable upstream API.
- **Mock Fallback**: Automatically falls back to a sample PDF response if the upstream API is unreachable.
- **WAR Packaging**: Includes all dependencies for standalone execution.

## Configuration

The application is configured via `src/main/resources/application.properties`. You can override these settings using Environment Variables.

### Environment Variables

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `LASERFICHE_URL` | The full URL of the upstream API endpoint. | `https://headq-lfwb-t.awb.local/LaserficheLOS/api/Values/GetDocument` |
| `LASERFICHE_AUTH` | The Authorization header value (e.g., Basic or Bearer token). | `Basic QVdCQU5LXHN2Yy1sZi10Om5ia0AxMjM0IQ==` |
| `SERVER_PORT` | The HTTP port the application listens on. | `9900` |

### Usage Example

Running with default settings (Port 9900, Mock Data fallack in dev env):
```bash
java -jar target/urlEncrypt-0.0.1-SNAPSHOT.war
```

Running with custom configuration:
```bash
export LASERFICHE_URL="https://api.example.com/v1/documents"
export LASERFICHE_AUTH="Bearer my-token-123"
export SERVER_PORT=8080

java -jar target/urlEncrypt-0.0.1-SNAPSHOT.war
```

## API Endpoint

### Get Document
**URL**: `/?id={CaseID}`
**Method**: `GET`

**Parameters**:
- `id` (required): The Case ID lookup value.

**Response**:
- `200 OK`: Returns the PDF file bytes.
- `Content-Type`: `application/pdf`
