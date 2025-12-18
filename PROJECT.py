#!/usr/bin/env python3
# Импорт необходимых модулей Python
import socket  # Модуль для сетевых соединений
import threading  # Модуль для многопоточности
import argparse  # Модуль для парсинга аргументов командной строки
import sys  # Модуль для системных функций
import time  # Модуль для работы со временем
import ipaddress  # Модуль для работы с IP-адресами

# Шаг 1: Создаем словарь с общеизвестными портами и сервисами
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP Proxy"
}

# Шаг 2: Создаем класс для сканирования портов
class PortScanner:
    """Класс для сканирования портов на целевом хосте"""
    
    def __init__(self, target_host, timeout=2):
        """Инициализируем сканер с целевым хостом и таймаутом"""
        self.target_host = target_host  # Сохраняем целевой хост
        self.timeout = timeout  # Сохраняем таймаут соединения
        self.results = []  # Создаем список для хранения результатов
    
    # Шаг 3: Метод для сканирования одного порта
    def scan_single_port(self, port, service_detection=False):
        """Сканирует один порт и возвращает результат"""
        start_time = time.time()  # Засекаем время начала сканирования
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Создаем TCP сокет
        sock.settimeout(self.timeout)  # Устанавливаем таймаут для сокета
        
        try:
            # Пытаемся подключиться к порту
            result = sock.connect_ex((self.target_host, port))  # connect_ex возвращает код ошибки
            response_time = time.time() - start_time  # Вычисляем время отклика
            
            if result == 0:  # Код 0 означает успешное подключение
                status = "OPEN"  # Порт открыт
                # Если включено определение сервисов, определяем сервис
                service = self.get_service_name(port) if service_detection else "Unknown"
                sock.close()  # Закрываем соединение
            else:  # Любой другой код означает ошибку
                status = "CLOSED"  # Порт закрыт
                service = "Unknown"  # Сервис неизвестен
                
        except socket.timeout:  # Если истек таймаут
            status = "FILTERED"  # Порт фильтруется (фаервол)
            service = "Unknown"  # Сервис неизвестен
            response_time = self.timeout  # Время отклика равно таймауту
            
        except Exception as e:  # Обрабатываем любые другие ошибки
            status = "ERROR"  # Статус ошибки
            service = str(e)[:50]  # Сохраняем сообщение об ошибке
            response_time = 0.0  # Время отклика 0
            
        finally:
            sock.close()  # Всегда закрываем сокет
            
        return (port, status, service, round(response_time, 3))  # Возвращаем результат
    
    # Шаг 4: Метод для определения сервиса по порту
    def get_service_name(self, port):
        """Определяет название сервиса по номеру порта"""
        return COMMON_PORTS.get(port, "Unknown")  # Возвращаем сервис или "Unknown"
    
    # Шаг 5: Метод для сканирования диапазона портов
    def scan_range(self, start_port, end_port, max_threads=100, service_detection=False):
        """Сканирует диапазон портов с использованием многопоточности"""
        self.results = []  # Очищаем предыдущие результаты
        ports_to_scan = range(start_port, end_port + 1)  # Создаем диапазон портов
        
        def worker(port):  # Функция-воркер для каждого потока
            return self.scan_single_port(port, service_detection)  # Сканируем один порт
        
        threads = []  # Список для хранения потоков
        results_lock = threading.Lock()  # Блокировка для безопасного доступа к результатам
        
        # Создаем и запускаем потоки
        for port in ports_to_scan:
            thread = threading.Thread(  # Создаем новый поток
                target=lambda p=port: self._save_result(worker(p), results_lock)  # Функция потока
            )
            threads.append(thread)  # Добавляем поток в список
            thread.start()  # Запускаем поток
            
            # Ограничиваем количество одновременно работающих потоков
            if len(threads) >= max_threads:
                for t in threads:  # Ждем завершения всех потоков
                    t.join()  # Блокируем выполнение до завершения потока
                threads = []  # Очищаем список потоков
        
        # Ждем завершения оставшихся потоков
        for thread in threads:
            thread.join()  # Блокируем выполнение до завершения потока
            
        return self.results  # Возвращаем результаты
    
    # Шаг 6: Вспомогательный метод для сохранения результатов
    def _save_result(self, result, lock):
        """Сохраняет результат сканирования потокобезопасно"""
        with lock:  # Блокируем доступ к списку результатов
            self.results.append(result)  # Добавляем результат в список

# Шаг 7: Функция для валидации входных данных
def validate_input(host, start_port, end_port):
    """Проверяет корректность входных параметров"""
    try:
        # Проверяем, является ли host валидным IP или доменным именем
        try:
            ipaddress.ip_address(host)  # Проверяем, является ли host IP-адресом
        except ValueError:
            socket.gethostbyname(host)  # Пробуем разрешить доменное имя
        
        # Проверяем корректность портов
        if not (1 <= start_port <= 65535):  # Проверяем начальный порт
            return False, "Начальный порт должен быть в диапазоне 1-65535"
        if not (1 <= end_port <= 65535):  # Проверяем конечный порт
            return False, "Конечный порт должен быть в диапазоне 1-65535"
        if start_port > end_port:  # Проверяем, что начальный порт меньше конечного
            return False, "Начальный порт должен быть меньше или равен конечному"
            
        return True, "OK"  # Все проверки пройдены
        
    except socket.gaierror:  # Ошибка разрешения доменного имени
        return False, f"Не удается разрешить хост: {host}"
    except Exception as e:  # Любая другая ошибка
        return False, f"Ошибка валидации: {str(e)}"

# Шаг 8: Функция для вывода результатов
def display_results(results, show_all=False):
    """Выводит результаты сканирования в удобном формате"""
    print("\n" + "="*60)  # Выводим разделительную линию
    print("РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ ПОРТОВ")  # Заголовок
    print("="*60)  # Выводим разделительную линию
    
    # Фильтруем открытые порты
    open_ports = [r for r in results if r[1] == "OPEN"]  # Используем list comprehension
    
    if show_all:  # Если нужно показать все порты
        print(f"\nВсего просканировано портов: {len(results)}")  # Общее количество
        print("-"*60)  # Разделитель
        for port, status, service, resp_time in results:  # Перебираем все результаты
            color = "\033[92m" if status == "OPEN" else "\033[91m"  # Выбираем цвет
            reset = "\033[0m"  # Сброс цвета
            print(f"{color}Порт {port:5d}: {status:10s} | Сервис: {service:15s} | "
                  f"Время: {resp_time:5.3f} сек{reset}")  # Выводим результат
    else:  # Если показываем только открытые порты
        if open_ports:  # Если есть открытые порты
            print(f"\nНайдено открытых портов: {len(open_ports)}")  # Количество открытых портов
            print("-"*60)  # Разделитель
            for port, status, service, resp_time in open_ports:  # Перебираем открытые порты
                print(f"\033[92mПорт {port:5d}: {service:15s} | "
                      f"Время отклика: {resp_time:5.3f} сек\033[0m")  # Выводим результат
        else:  # Если нет открытых портов
            print("\n\033[93mОткрытых портов не найдено\033[0m")  # Сообщение об отсутствии
    
    # Выводим статистику
    print("\n" + "-"*60)  # Разделитель
    print("СТАТИСТИКА:")  # Заголовок статистики
    total = len(results)  # Всего портов
    open_count = len(open_ports)  # Открытых портов
    closed_count = len([r for r in results if r[1] == "CLOSED"])  # Закрытых портов
    filtered_count = len([r for r in results if r[1] == "FILTERED"])  # Фильтруемых портов
    
    print(f"Всего: {total} | Открыто: {open_count} | "
          f"Закрыто: {closed_count} | Фильтруется: {filtered_count}")  # Статистика

# Шаг 9: Основная функция программы
def main():
    """Главная функция с CLI интерфейсом"""
    # Создаем парсер аргументов командной строки
    parser = argparse.ArgumentParser(
        description='Сканер портов - утилита для проверки открытых портов на хосте',
        epilog='Примеры использования:\n'
               '  python port_scanner.py localhost -p 1-100\n'
               '  python port_scanner.py 192.168.1.1 -p 20-443 -s\n'
               '  python port_scanner.py example.com -p 80,443,8080'
    )
    
    # Определяем обязательные и опциональные аргументы
    parser.add_argument('host', help='Целевой хост или IP-адрес для сканирования')  # Обязательный аргумент
    parser.add_argument('-p', '--ports', default='1-1000',  # Аргумент для портов
                       help='Диапазон портов для сканирования (по умолчанию: 1-1000)')
    parser.add_argument('-t', '--threads', type=int, default=50,  # Аргумент для потоков
                       help='Количество потоков для сканирования (по умолчанию: 50)')
    parser.add_argument('-s', '--service', action='store_true',  # Флаг определения сервисов
                       help='Определять сервисы на открытых портах')
    parser.add_argument('-a', '--all', action='store_true',  # Флаг показа всех портов
                       help='Показывать все порты (включая закрытые)')
    parser.add_argument('--timeout', type=float, default=2.0,  # Аргумент для таймаута
                       help='Таймаут соединения в секундах (по умолчанию: 2.0)')
    
    # Парсим аргументы из командной строки
    args = parser.parse_args()
    
    # Шаг 10: Обрабатываем диапазон портов
    if '-' in args.ports:  # Если указан диапазон через дефис
        try:
            start_port, end_port = map(int, args.ports.split('-'))  # Разделяем и преобразуем в числа
        except ValueError:  # Если не удалось преобразовать в числа
            print("Ошибка: некорректный формат диапазона портов. Используйте 'начальный-конечный'")
            sys.exit(1)  # Завершаем программу с кодом ошибки
    elif ',' in args.ports:  # Если указаны конкретные порты через запятую
        try:
            port_list = [int(p.strip()) for p in args.ports.split(',')]  # Создаем список портов
            start_port, end_port = min(port_list), max(port_list)  # Определяем диапазон
        except ValueError:  # Если не удалось преобразовать в числа
            print("Ошибка: некорректный список портов. Используйте 'порт1,порт2,порт3'")
            sys.exit(1)  # Завершаем программу с кодом ошибки
    else:  # Если указан один порт
        try:
            start_port = end_port = int(args.ports)  # Оба порта равны указанному
        except ValueError:  # Если не удалось преобразовать в число
            print("Ошибка: порт должен быть числом")
            sys.exit(1)  # Завершаем программу с кодом ошибки
    
    # Шаг 11: Валидируем входные данные
    print(f"\nПроверка параметров...")  # Информационное сообщение
    is_valid, message = validate_input(args.host, start_port, end_port)  # Вызываем валидацию
    if not is_valid:  # Если валидация не пройдена
        print(f"Ошибка: {message}")  # Выводим сообщение об ошибке
        sys.exit(1)  # Завершаем программу с кодом ошибки
    
    # Шаг 12: Создаем сканер и начинаем сканирование
    print(f"Начинаю сканирование {args.host} (порты {start_port}-{end_port})...")  # Информация
    print(f"Используется {args.threads} потоков, таймаут: {args.timeout} сек")  # Параметры
    
    if args.service:  # Если включено определение сервисов
        print("Определение сервисов: ВКЛЮЧЕНО")  # Информация
    
    scanner = PortScanner(args.host, args.timeout)  # Создаем объект сканера
    start_time = time.time()  # Засекаем время начала сканирования
    
    try:
        # Запускаем сканирование
        results = scanner.scan_range(  # Вызываем метод сканирования
            start_port, end_port,  # Диапазон портов
            args.threads,  # Количество потоков
            args.service  # Определение сервисов
        )
        
        scan_time = time.time() - start_time  # Вычисляем время сканирования
        
        # Шаг 13: Выводим результаты
        display_results(results, args.all)  # Вызываем функцию отображения результатов
        print(f"\nСканирование завершено за {scan_time:.2f} секунд")  # Время выполнения
        
    except KeyboardInterrupt:  # Если пользователь нажал Ctrl+C
        print("\n\nСканирование прервано пользователем (Ctrl+C)")  # Сообщение
        sys.exit(0)  # Завершаем программу нормально
        
    except Exception as e:  # Любая другая ошибка
        print(f"\nПроизошла ошибка при сканировании: {str(e)}")  # Сообщение об ошибке
        sys.exit(1)  # Завершаем программу с кодом ошибки

# Шаг 14: Точка входа в программу
if __name__ == "__main__":
    main()  # Вызываем главную функцию