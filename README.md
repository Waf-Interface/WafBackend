**WafBackend** is a simple backend built with FastAPI. It connects Nginx’s ModSecurity to a clear API. This helps you manage web security settings easily.

### Status: <Beta, writting doc...>
# WafBackend


## Features

- **FastAPI Routers**: Clean routes for tasks like authentication, deployment, system info, WebSocket and WAF management.
- **CORS Middleware**: Lets different clients talk to the server safely.
- **RSA Key Generation**: Creates RSA keys automatically for secure use.
- **Database Support**: Uses SQLAlchemy to handle multiple databases.
- **Backup Service**: Keeps your data safe with regular backups.

## Quick Start

1. **Clone the repo**:
   ```bash
   git clone https://github.com/Waf-Interface/WafBackend.git
   cd WafBackend
   ```

2. **Go to the test folder**:
   ```bash
   cd test
   ```

3. **Run the install script**:
   ```bash
   python test/in.py
   ```
   This will install needed packages and start the FastAPI server.

## Usage

After the server starts, open:

```
http://localhost:8081/docs
```

Here, you can see and test all the API endpoints.

## Using This Backend

You can also run tests or use the backend code found in:

```
https://github.com/Waf-Interface/WafBackend/tree/main/test
```

For a quick install or deploy, check the script:

```
https://github.com/Waf-Interface/WafBackend/blob/main/test/test/in.py
```

## License

This project uses the MIT License.
