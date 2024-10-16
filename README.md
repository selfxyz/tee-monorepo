# Nitro Enclave Logger

A simple and efficient logging server designed to run inside the host machine to stream logs from the AWS Nitro Enclave.

1. GET `/stream` -- Creates an SSE connection which can be listened by the client to access realtime logs
2. GET `/logs?log_id=50&offset=10` -- Responds with the logs starting with `offset` number of logs starting from log id = `log_id-1`

### Building the Server

1. Clone the repository:

    ```bash
    git clone https://github.com/your-repo/nitro-enclave-logger.git
    ```

2. Navigate to the project directory:

    ```bash
    cd nitro-enclave-logger
    ```

3. Build the project in release mode:

    ```bash
    cargo build --release
    ```

### Running the Server

Before running the server, you need to grant it permission to bind to server port (default = 516). This is required because ports below 1024 are privileged, and binding to them normally requires root access.

#### Notes:

1. Since the program by default uses port 516, run the command below to allow the program to bind to this privileged port:

    ```bash
    sudo setcap 'cap_net_bind_service=+ep' ./target/release/logger
    ```

2. After setting the capabilities, you can run the server:

    ```bash
    ./target/release/logger
    ```

3. The server will start and listen for http requests on port 516.

## Additional Information

- Ensure your firewall and security groups allow traffic on port 516 if you intend to access the server from outside the host machine.
- To reapply the capability (`setcap`) on the binary, run the command again after each rebuild.
