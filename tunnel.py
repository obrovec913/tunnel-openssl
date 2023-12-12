import socket
from OpenSSL import SSL


def create_ssl_context(cipher_algorithm):
    # Создание объекта контекста SSL с выбранным алгоритмом шифрования
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.set_cipher_list(cipher_algorithm)
    return context

def create_ssl_tunnel(server_host, server_port, local_port, cipher_algorithm):
    # Создание TCP-сервера для локального хоста и порта
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', local_port))
    server_socket.listen(1)

    print(f"Listening on localhost:{local_port}")

    try:
        while True:
            # Принятие входящего соединения от клиента
            client_socket, client_address = server_socket.accept()
            print(f"Accepted connection from {client_address}")

            # Создание SSL-соединения с выбранным алгоритмом шифрования
            ssl_context = create_ssl_context(cipher_algorithm)
            ssl_socket = SSL.Connection(ssl_context, client_socket)
            ssl_socket.set_accept_state()
            ssl_socket.do_handshake()

            # Подключение к удаленному серверу
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((server_host, server_port))

            # Запуск двунаправленного обмена данными между клиентом и сервером
            try:
                while True:
                    data = ssl_socket.recv(4096)
                    if not data:
                        break
                    remote_socket.sendall(data)

                    remote_data = remote_socket.recv(4096)
                    if not remote_data:
                        break
                    ssl_socket.sendall(remote_data)
            finally:
                # Закрытие соединений
                ssl_socket.close()
                remote_socket.close()
                print(f"Closed connection from {client_address}")
    finally:
        # Закрытие серверного сокета
        server_socket.close()

if __name__ == "__main__":
    server_host = "example.com"  # Замените на реальный хост
    server_port = 443  # Замените на реальный порт
    local_port = 8443  # Локальный порт, к которому будет подключаться клиент

    cipher_algorithm = "AES256-SHA"  # Замените на нужный алгоритм шифрования

    create_ssl_tunnel(server_host, server_port, local_port, cipher_algorithm)
