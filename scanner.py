import nmap  # Import biblioteki nmap do skanowania sieci
from tqdm import tqdm  # Import biblioteki tqdm do wyświetlania paska postępu
import ipaddress  # Import biblioteki ipaddress do walidacji adresów IP
import re  # Import biblioteki re do wyrażeń regularnych


def validate_ip(ip):
    try:
        # Próba konwersji ciągu znaków na adres IP
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port_range(port_range):
    # Sprawdzenie, czy zakres portów ma poprawny format
    if not re.match(r'^\d+-\d+$', port_range):
        return False

    # Podział zakresu portów na początek i koniec
    start, end = map(int, port_range.split('-'))
    if start > end or start < 1 or end > 65535:
        return False
    return True


def validate_line(line):
    try:
        # Podział linii na adres IP, zakres portów TCP i UDP
        ip, tcp_ports, udp_ports = line.strip().split(',')
        if not validate_ip(ip):
            print(f"Błąd: Nieprawidłowy adres IP: {ip}")
            return False
        if not validate_port_range(tcp_ports):
            print(f"Błąd: Nieprawidłowy zakres portów TCP: {tcp_ports}")
            return False
        if not validate_port_range(udp_ports):
            print(f"Błąd: Nieprawidłowy zakres portów UDP: {udp_ports}")
            return False
        return True
    except ValueError:
        print(f"Błąd: Nieprawidłowy format linii: {line.strip()}")
        return False


def scan_ports(nm, ip, ports, scan_type):
    # Inicjalizacja pustego słownika na wyniki
    results = {}
    # Podział portów na partie po 10
    port_batches = [ports[i:i + 10] for i in range(0, len(ports), 10)]
    for batch in tqdm(port_batches, desc=f"Scanning {scan_type[1:]} ports on {ip}", unit="batch"):

        # Łączenie portów z partii w string oddzielony przecinkami
        port_str = ','.join(map(str, batch))
        try:
            nm.scan(ip, port_str, arguments=scan_type)  # Skanowanie portów przy użyciu nmap
            scan_data = nm[ip]  # Pobranie danych skanowania dla danego adresu IP

            for protocol in scan_data.all_protocols():  # Iteracja po protokołach (TCP/UDP)
                if protocol not in results:
                    results[protocol] = {}  # Inicjalizacja pustego słownika dla danego protokołu
                scanned_ports = list(scan_data[protocol].keys()) if protocol in scan_data else []
                # Pobranie listy zeskanowanych portów dla danego protokołu
                for port in batch:  # Iteracja po portach z danej partii
                    if port in scanned_ports:  # Sprawdzenie, czy port został zeskanowany
                        result = {
                            'state': scan_data[protocol][port]['state'],  # Stan portu (otwarty/zamknięty/filtrowany)
                            'service': scan_data[protocol][port]['name'],  # Nazwa usługi działającej na porcie
                            'reason': scan_data[protocol][port].get('reason', ''),  # Powód stanu portu
                            'conf': scan_data[protocol][port].get('conf', 0),
                            # Współczynnik pewności dla wykrytej usługi
                        }
                    else:  # Jeśli port nie został zeskanowany
                        result = {
                            'state': 'unknown',
                            'service': 'unknown',
                            'reason': '',
                            'conf': 0,
                        }
                    results[protocol][port] = result  # Dodanie wyników skanowania dla danego portu do słownika

        except Exception as e:
            return {"error": str(e)}

    return results


def main(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()

        nm = nmap.PortScanner()  # Utworzenie instancji skanera nmap

        with open(output_file, 'w') as f:
            for line in lines:
                if validate_line(line):
                    ip, tcp_ports, udp_ports = line.strip().split(',')
                    tcp_ports = list(
                        range(int(tcp_ports.split('-')[0]),
                              int(tcp_ports.split('-')[1]) + 1))  # Utworzenie listy portów TCP
                    udp_ports = list(
                        range(int(udp_ports.split('-')[0]),
                              int(udp_ports.split('-')[1]) + 1))  # Utworzenie listy portów UDP

                    f.write(f"Scanning ports for IP: {ip}\n")  # Zapis informacji o skanowanym adresie IP

                    # Scan TCP ports
                    f.write("Scanning TCP ports...\n")
                    tcp_results = scan_ports(nm, ip, tcp_ports, '-sT')  # Wywołanie funkcji skanującej porty TCP
                    if 'error' in tcp_results:  # Sprawdzenie, czy wystąpił błąd podczas skanowania
                        f.write(f"Error scanning TCP ports: {tcp_results['error']}\n")  # Zapis informacji o błędzie
                    else:
                        for port in tcp_ports:  # Iteracja po portach TCP
                            details = tcp_results.get('tcp', {}).get(port, {})  # Pobranie szczegółów skanowania dla danego portu
                            state = details.get('state', 'unknown')  # Pobranie stanu portu
                            service = details.get('service', 'unknown')  # Pobranie nazwy usługi
                            reason = details.get('reason', '')  # Pobranie powodu stanu portu
                            conf = details.get('conf', 0)  # Pobranie współczynnika pewności
                            f.write(
                                f"Port {port}/TCP: State={state}, Service={service}, Reason={reason}, Conf={conf}\n")
                            # Zapis informacji o porcie TCP do pliku

                    # Scan UDP ports
                    f.write("Scanning UDP ports...\n")
                    udp_results = scan_ports(nm, ip, udp_ports, '-sU')  # Wywołanie funkcji skanującej porty UDP
                    if 'error' in udp_results:  # Sprawdzenie, czy wystąpił błąd podczas skanowania
                        f.write(f"Error scanning UDP ports: {udp_results['error']}\n")  # Zapis informacji o błędzie
                    else:
                        for port in udp_ports:
                            details = udp_results.get('udp', {}).get(port, {})
                            state = details.get('state', 'unknown')  # Pobranie stanu portu
                            service = details.get('service', 'unknown')  # Pobranie nazwy usługi
                            reason = details.get('reason', '')  # Pobranie powodu stanu portu
                            conf = details.get('conf', 0)  # Pobranie współczynnika pewności
                            f.write(
                                f"Port {port}/UDP: State={state}, Service={service}, Reason={reason}, Conf={conf}\n")
                            # Zapis informacji o porcie UDP do pliku

                    f.write("\n")

        print("Scan completed. Results saved to",
              output_file)
    except Exception as e:
        print("An error occurred:", e)


if __name__ == "__main__":
    input_file = input("Enter input file path: ").strip()
    output_file = input(
        "Enter output file path: ").strip()
    main(input_file, output_file)
