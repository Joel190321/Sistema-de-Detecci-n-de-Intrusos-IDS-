from scapy.all import sniff, IP, TCP, UDP, ICMP
import sqlite3
import datetime
import json
from itertools import groupby


DATABASE = 'ids.db'


alerts = []
capture_active = False

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  source_ip TEXT,
                  destination_ip TEXT,
                  protocol TEXT,
                  port INTEGER,
                  description TEXT,
                  severity TEXT,
                  attack_type TEXT,
                  risk_score INTEGER,
                  recommendation TEXT)''')
    conn.commit()
    conn.close()

def log_alert(source_ip, destination_ip, protocol, port, description, severity, attack_type, risk_score, recommendation):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO alerts (timestamp, source_ip, destination_ip, protocol, port, description, severity, attack_type, risk_score, recommendation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (timestamp, source_ip, destination_ip, protocol, port, description, severity, attack_type, risk_score, recommendation))
    conn.commit()
    conn.close()

    
    alert = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "port": port,
        "description": description,
        "severity": severity,
        "attack_type": attack_type,
        "risk_score": risk_score,
        "recommendation": recommendation
    }
    alerts.append(alert)
    print(f"ALERT: {description} from {source_ip} to {destination_ip} at {timestamp}")

def detect_intrusion(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto
        port = None
        description = ""
        severity = "medium"
        attack_type = ""
        risk_score = 5  
        recommendation = "Revisar el tráfico sospechoso."

        
        if TCP in packet:
            port = packet[TCP].dport
            if packet[TCP].flags == 0x03:  
                description = "Suspicious TCP packet with SYN and FIN flags"
                attack_type = "Port Scan"
                severity = "high"
                risk_score = 9
                recommendation = "Bloquear la IP fuente y revisar reglas de firewall."
            elif packet[TCP].dport == 22:  
                description = "Suspicious SSH traffic"
                attack_type = "Brute Force"
                severity = "high"
                risk_score = 8
                recommendation = "Implementar autenticación de dos factores y bloquear la IP fuente."
        elif UDP in packet:
            port = packet[UDP].dport
            if packet[UDP].dport == 53:  
                description = "Suspicious DNS traffic"
                attack_type = "DNS Spoofing"
                severity = "medium"
                risk_score = 6
                recommendation = "Verificar la configuración del servidor DNS."
        elif ICMP in packet:
            description = "Suspicious ICMP traffic"
            attack_type = "Ping Sweep"
            severity = "low"
            risk_score = 4
            recommendation = "Revisar reglas de firewall para tráfico ICMP."

        if len(packet) > 1500:  
            description = "Suspicious large packet size"
            attack_type = "Buffer Overflow"
            severity = "high"
            risk_score = 7
            recommendation = "Revisar la configuración de los servicios de red."

        
        if description:
            log_alert(source_ip, destination_ip, protocol, port, description, severity, attack_type, risk_score, recommendation)

        
        if len(alerts) >= 5:
            global capture_active
            capture_active = False
            print("Captura detenida: se han generado 20 alertas.")
            generate_html_report()

def start_capture(interface):
    global capture_active
    capture_active = True
    print(f"Starting IDS on interface {interface}...")
    sniff(iface=interface, prn=detect_intrusion, stop_filter=lambda x: not capture_active)

def generate_html_report():
    
    severity_data = {
        "high": len([a for a in alerts if a["severity"] == "high"]),
        "medium": len([a for a in alerts if a["severity"] == "medium"]),
        "low": len([a for a in alerts if a["severity"] == "low"]),
    }

    attack_type_data = {k: len(list(v)) for k, v in groupby(sorted([a["attack_type"] for a in alerts]))}

    
    with open("report.html", "w", encoding="utf-8") as file:
        file.write(f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reporte de Alertas - IDS</title>
            <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body class="bg-gray-100 p-8">
            <div class="max-w-7xl mx-auto">
                <h1 class="text-3xl font-bold mb-8 text-center">Reporte de Alertas - Sistema de Detección de Intrusos (IDS)</h1>

                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
                    <!-- Gráfico de Severidad -->
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h2 class="text-xl font-semibold mb-4">Distribución de Severidad</h2>
                        <canvas id="severityChart"></canvas>
                    </div>

                    
                    <div class="bg-white p-6 rounded-lg shadow-md">
                        <h2 class="text-xl font-semibold mb-4">Tipos de Ataque Detectados</h2>
                        <canvas id="attackTypeChart"></canvas>
                    </div>
                </div>

                
                <div class="bg-white p-6 rounded-lg shadow-md">
                    <h2 class="text-xl font-semibold mb-4">Detalles de las Alertas</h2>
                    <div id="alerts" class="space-y-4">
        """)

        
        for alert in alerts:
            file.write(f"""
                        <div class="p-4 rounded-lg shadow-md ${
                            'bg-red-100 border-l-4 border-red-500' if alert['severity'] == 'high' else
                            'bg-yellow-100 border-l-4 border-yellow-500' if alert['severity'] == 'medium' else
                            'bg-blue-100 border-l-4 border-blue-500'
                        }">
                            <div class="flex justify-between items-center">
                                <div>
                                    <strong class="text-gray-800">Fecha y Hora:</strong> {alert['timestamp']}<br>
                                    <strong class="text-gray-800">Origen:</strong> {alert['source_ip']}<br>
                                    <strong class="text-gray-800">Destino:</strong> {alert['destination_ip']}<br>
                                    <strong class="text-gray-800">Protocolo:</strong> {alert['protocol']}<br>
                                    <strong class="text-gray-800">Puerto:</strong> {alert['port']}<br>
                                    <strong class="text-gray-800">Descripción:</strong> {alert['description']}<br>
                                    <strong class="text-gray-800">Tipo de Ataque:</strong> {alert['attack_type']}<br>
                                    <strong class="text-gray-800">Severidad:</strong> {alert['severity']}<br>
                                    <strong class="text-gray-800">Puntaje de Riesgo:</strong> {alert['risk_score']}<br>
                                    <strong class="text-gray-800">Recomendación:</strong> {alert['recommendation']}
                                </div>
                            </div>
                        </div>
            """)

        file.write(f"""
                    </div>
                </div>
            </div>

            <script>
                const severityData = {json.dumps(severity_data)};
                const attackTypeData = {json.dumps(attack_type_data)};

                const severityChart = new Chart(document.getElementById("severityChart"), {{
                    type: "doughnut",
                    data: {{
                        labels: ["Alta", "Media", "Baja"],
                        datasets: [{{
                            label: "Severidad",
                            data: [severityData.high, severityData.medium, severityData.low],
                            backgroundColor: ["#EF4444", "#F59E0B", "#3B82F6"],
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        plugins: {{
                            legend: {{
                                position: "bottom",
                            }},
                        }},
                    }},
                }});

                const attackTypeChart = new Chart(document.getElementById("attackTypeChart"), {{
                    type: "bar",
                    data: {{
                        labels: Object.keys(attackTypeData),
                        datasets: [{{
                            label: "Cantidad",
                            data: Object.values(attackTypeData),
                            backgroundColor: ["#10B981", "#3B82F6", "#F59E0B", "#EF4444"],
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        plugins: {{
                            legend: {{
                                display: false,
                            }},
                        }},
                        scales: {{
                            y: {{
                                beginAtZero: true,
                            }},
                        }},
                    }},
                }});
            </script>
        </body>
        </html>
        """)

    print("Reporte HTML generado: report.html")

if __name__ == "__main__":
    init_db()
    interface = "Wi-Fi"  
    start_capture(interface)