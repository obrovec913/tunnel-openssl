import socket
import sys
import select

PORT= 5412
host = '192.168.1.5'
def main():
    # Хост и порт для подключения (замените на нужные значения)
    
    

    # Создание сокета и подключение к серверу
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        s.connect((host, PORT))
        print(f"Connected to {host}:{PORT}")
    except BlockingIOError:
        pass

    # Основной цикл программы
    while True:
        # Проверяем, есть ли данные для чтения или записи
        try:
            readable, writable, _ = select.select([s], [s], [])
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        

        # Отправка данных на сервер
        if sys.stdin in readable:
            message = input("Введите сообщение: ").strip()
            if message:
                s.sendall(message.encode())

        # Получение данных от сервера
        if s in readable:
            data = s.recv(1024)
            if not data:
                print("Server closed connection.")
                break
            print("Received:", data.decode())

    s.close()

if __name__ == "__main__":
    main()
