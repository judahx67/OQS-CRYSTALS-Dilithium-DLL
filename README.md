Library: https://github.com/open-quantum-safe/liboqs Cross compiled for Windows using Ubuntu 22

const char* keygen(const char* private_key_file);
const char* sign(const char* message, const char* private_key_file);
bool verify(const char* message, const char* signature_hex, const char* public_key_hex);
