import tkinter as tk
import random
import time

# -----------------------------
# Configuración básica
# -----------------------------

WINDOW_WIDTH = 950
WINDOW_HEIGHT = 550

PACKET_SPEED = 3
SPAWN_INTERVAL_MS = 1100
LOG_MAX_LINES = 14

PROTOCOLS = [
    ("HTTP", 80),
    ("SSH", 22),
    ("TELNET", 23),
    ("MALWARE", -1),
    ("DNS", 53),
]

# -----------------------------
# Clase Packet (paquete de red)
# -----------------------------

class Packet:
    def __init__(self, canvas, proto, port, color, y, rules, speed_boost=0):
        self.canvas = canvas
        self.proto = proto
        self.port = port
        self.color = color
        self.y = y
        self.rules = rules

        self.x = 40
        self.radius = 10
        self.speed_boost = speed_boost

        self.id = self.canvas.create_oval(
            self.x - self.radius, self.y - self.radius,
            self.x + self.radius, self.y + self.radius,
            fill=self.color, outline=""
        )

        self.text_id = self.canvas.create_text(
            self.x, self.y - 18,
            text=self.proto,
            fill="white",
            font=("Consolas", 8)
        )

        self.alive = True
        self.result = None

    def step(self, firewall_x, server_x):
        if not self.alive:
            return

        speed = PACKET_SPEED + self.speed_boost

        if self.x < firewall_x:
            self.x += speed
            self.canvas.move(self.id, speed, 0)
            self.canvas.move(self.text_id, speed, 0)
        else:
            if self.result is None:
                self.result = self.apply_rules()

            if self.result == "blocked":
                self.x += speed
                self.y += speed
                self.canvas.move(self.id, speed, speed)
                self.canvas.move(self.text_id, speed, speed)
                if self.y > WINDOW_HEIGHT + 20:
                    self.destroy()
            else:
                if self.x < server_x:
                    self.x += speed
                    self.canvas.move(self.id, speed, 0)
                    self.canvas.move(self.text_id, speed, 0)
                else:
                    self.destroy()

    def apply_rules(self):
        if self.proto == "HTTP":
            return "allowed" if self.rules["allow_http"] else "blocked"
        elif self.proto == "SSH":
            return "allowed" if self.rules["allow_ssh"] else "blocked"
        elif self.proto == "TELNET":
            return "blocked" if self.rules["block_telnet"] else "allowed"
        elif self.proto == "MALWARE":
            return "blocked" if self.rules["block_malware"] else "allowed"
        elif self.proto == "DNS":
            return "blocked" if self.rules["block_dns"] else "allowed"
        return "blocked"

    def destroy(self):
        self.alive = False
        self.canvas.delete(self.id)
        self.canvas.delete(self.text_id)


# -----------------------------
# Clase principal del simulador
# -----------------------------

class FirewallSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Visual Interactivo —  Victor Lopez")

        self.canvas = tk.Canvas(root, width=WINDOW_WIDTH, height=WINDOW_HEIGHT, bg="#0f172a")
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.side_frame = tk.Frame(root, bg="#020617")
        self.side_frame.pack(side=tk.RIGHT, fill=tk.Y)

        self.rules = {
            "allow_http": True,
            "allow_ssh": True,
            "block_telnet": True,
            "block_malware": True,
            "block_dns": False,
        }

        self.packets = []
        self.last_spawn_time = time.time()

        self.allowed_count = 0
        self.blocked_count = 0
        self.pps_counter = 0
        self.last_pps_time = time.time()
        self.current_pps = 0

        self.cpu_usage = 30
        self.ram_usage = 40
        self.last_resource_update = time.time()

        self.attack_mode = False
        self.attack_end_time = 0
        self.attack_banner = None
        self.attack_button_flash_state = False

        self._build_ui()
        self._draw_static_elements()

        self.running = True
        self.update_loop()

    # -------------------------
    # BOTÓN MODERNO (CANVAS)
    # -------------------------

    def create_modern_button(self, parent, text, command):
        canvas = tk.Canvas(parent, width=260, height=50, bg="#020617", highlightthickness=0)
        canvas.pack(pady=12)

        for i in range(40):
            color = f"#{(6+i):02x}{(78+i):02x}{(59+i):02x}"
            canvas.create_rectangle(5, 5+i, 255, 6+i, outline=color, fill=color)

        canvas.create_text(130, 25, text=text, fill="white", font=("Consolas", 13, "bold"))

        def on_click(event):
            command()

        canvas.bind("<Button-1>", on_click)
        return canvas

    # -------------------------
    # Construcción de UI
    # -------------------------

    def _build_ui(self):
        title = tk.Label(
            self.side_frame,
            text="Firewall\nSimulator",
            fg="white",
            bg="#020617",
            font=("Consolas", 20, "bold"),
            justify="center"
        )
        title.pack(pady=10)

        rules_label = tk.Label(
            self.side_frame,
            text="Firewall Rules",
            fg="#38bdf8",
            bg="#020617",
            font=("Consolas", 12, "bold")
        )
        rules_label.pack(pady=(10, 0))

        self.var_allow_http = tk.BooleanVar(value=True)
        self.var_allow_ssh = tk.BooleanVar(value=True)
        self.var_block_telnet = tk.BooleanVar(value=True)
        self.var_block_malware = tk.BooleanVar(value=True)
        self.var_block_dns = tk.BooleanVar(value=False)

        self._add_checkbox("ALLOW HTTP (80)", self.var_allow_http)
        self._add_checkbox("ALLOW SSH (22)", self.var_allow_ssh)
        self._add_checkbox("BLOCK TELNET (23)", self.var_block_telnet)
        self._add_checkbox("BLOCK MALWARE", self.var_block_malware)
        self._add_checkbox("BLOCK DNS (53)", self.var_block_dns)

        self.attack_btn = self.create_modern_button(
            self.side_frame,
            "⚠ ENABLE ATTACK MODE",
            self.start_attack_mode
        )

        stats_label = tk.Label(
            self.side_frame,
            text="Statistics",
            fg="#22c55e",
            bg="#020617",
            font=("Consolas", 12, "bold")
        )
        stats_label.pack()

        self.stats_text = tk.Label(
            self.side_frame,
            text="Accepted: 0\nBlocked: 0\nPPS: 0",
            fg="white",
            bg="#020617",
            font=("Consolas", 10),
            justify="left"
        )
        self.stats_text.pack(pady=(0, 10))

        resource_label = tk.Label(
            self.side_frame,
            text="Server Resources",
            fg="#fbbf24",
            bg="#020617",
            font=("Consolas", 12, "bold")
        )
        resource_label.pack()

        self.resource_text = tk.Label(
            self.side_frame,
            text="CPU: 30%\nRAM: 40%",
            fg="white",
            bg="#020617",
            font=("Consolas", 10)
        )
        self.resource_text.pack(pady=10)

        log_label = tk.Label(
            self.side_frame,
            text="Log",
            fg="#f97316",
            bg="#020617",
            font=("Consolas", 12, "bold")
        )
        log_label.pack()

        self.log_box = tk.Text(
            self.side_frame,
            width=40,
            height=LOG_MAX_LINES,
            bg="#020617",
            fg="#e5e7eb",
            font=("Consolas", 9)
        )
        self.log_box.pack(padx=5, pady=5)
        self.log_box.config(state=tk.DISABLED)

    def _add_checkbox(self, text, var):
        tk.Checkbutton(
            self.side_frame,
            text=text,
            variable=var,
            command=self.update_rules,
            fg="white",
            bg="#020617",
            selectcolor="#020617",
            activebackground="#020617",
            font=("Consolas", 10)
        ).pack(anchor="w", padx=10)

    # -------------------------
    # Dibujar elementos estáticos
    # -------------------------

    def _draw_static_elements(self):
        self.canvas.create_text(
            WINDOW_WIDTH // 2, 30,
            text="Firewall Network Simulator — Victor Lopez",
            fill="#e5e7eb",
            font=("Consolas", 16, "bold")
        )

        self.canvas.create_text(
            100, 70,
            text="Incoming Traffic",
            fill="#38bdf8",
            font=("Consolas", 12, "bold")
        )

        for i in range(3):
            y = 140 + i * 100
            self.canvas.create_rectangle(
                40, y - 20, 80, y + 20,
                outline="#4b5563", fill="#020617"
            )
            self.canvas.create_text(
                60, y,
                text=f"Host {i+1}",
                fill="#e5e7eb",
                font=("Consolas", 9)
            )

        self.firewall_x = WINDOW_WIDTH // 2
        self.firewall_rect = self.canvas.create_rectangle(
            self.firewall_x - 10, 100,
            self.firewall_x + 10, WINDOW_HEIGHT - 100,
            fill="#b91c1c", outline="#fecaca"
        )
        self.canvas.create_text(
            self.firewall_x, 90,
            text="FIREWALL",
            fill="#fecaca",
            font=("Consolas", 10, "bold")
        )

        self.server_x = WINDOW_WIDTH - 120
        self.canvas.create_rectangle(
            self.server_x - 50, WINDOW_HEIGHT // 2 - 50,
            self.server_x + 50, WINDOW_HEIGHT // 2 + 50,
            fill="#020617", outline="#22c55e", width=3
        )
        self.canvas.create_text(
            self.server_x, WINDOW_HEIGHT // 2,
            text="SERVER",
            fill="#22c55e",
            font=("Consolas", 12, "bold")
        )
        # -------------------------
        # Lógica del firewall
        # -------------------------

    def update_rules(self):
        self.rules["allow_http"] = self.var_allow_http.get()
        self.rules["allow_ssh"] = self.var_allow_ssh.get()
        self.rules["block_telnet"] = self.var_block_telnet.get()
        self.rules["block_malware"] = self.var_block_malware.get()
        self.rules["block_dns"] = self.var_block_dns.get()

    def spawn_packet(self):
        if self.attack_mode:
            proto = random.choice(["MALWARE", "TELNET"])
            speed_boost = 2
        else:
            proto, _ = random.choice(PROTOCOLS)
            speed_boost = 0

        port = {
            "HTTP": 80,
            "SSH": 22,
            "TELNET": 23,
            "MALWARE": -1,
            "DNS": 53,
        }[proto]

        color = {
            "HTTP": "#22c55e",
            "SSH": "#38bdf8",
            "TELNET": "#eab308",
            "MALWARE": "#ef4444",
            "DNS": "#a78bfa",
        }[proto]

        y = random.randint(140, WINDOW_HEIGHT - 80)
        p = Packet(self.canvas, proto, port, color, y, self.rules, speed_boost)
        self.packets.append(p)

        self.pps_counter += 1

    # -------------------------
    # MODO ATAQUE
    # -------------------------

    def start_attack_mode(self):
        if self.attack_mode:
            return

        self.attack_mode = True
        self.attack_end_time = time.time() + 5

        self.paint_button_red("⚠ ATAQUE EN CURSO")

        self.attack_banner = self.canvas.create_text(
            WINDOW_WIDTH // 2, 70,
            text="⚠ ATAQUE EN CURSO ⚠",
            fill="#f87171",
            font=("Consolas", 18, "bold")
        )

        self.canvas.itemconfig(self.firewall_rect, fill="#7f1d1d")

        self.attack_button_flash_state = True
        self.flash_attack_button()

        self.log_event("⚠ Modo Ataque activado: tráfico hostil detectado.", kind="block")

    def paint_button_red(self, text):
        canvas = self.attack_btn
        canvas.delete("all")
        for i in range(40):
            shade = f"#{(127+i):02x}{(29+i):02x}{(29+i):02x}"
            canvas.create_rectangle(5, 5+i, 255, 6+i, outline=shade, fill=shade)
        canvas.create_text(130, 25, text=text, fill="white", font=("Consolas", 13, "bold"))

    def paint_button_green(self, text):
        canvas = self.attack_btn
        canvas.delete("all")
        for i in range(40):
            color = f"#{(6+i):02x}{(78+i):02x}{(59+i):02x}"
            canvas.create_rectangle(5, 5+i, 255, 6+i, outline=color, fill=color)
        canvas.create_text(130, 25, text=text, fill="white", font=("Consolas", 13, "bold"))

    def flash_attack_button(self):
        if not self.attack_mode:
            return

        if self.attack_button_flash_state:
            self.paint_button_red("⚠ ATAQUE EN CURSO")
        else:
            self.paint_button_red("⚠ ATAQUE EN CURSO")

        self.attack_button_flash_state = not self.attack_button_flash_state
        self.root.after(300, self.flash_attack_button)

    # -------------------------
    # LOG (con fix)
    # -------------------------

    def log_event(self, text, kind="info"):
        prefix = {
            "info": "[INFO] ",
            "allow": "[ALLOW]",
            "block": "[BLOCK]",
        }.get(kind, "[INFO]")

        line = f"{prefix} {text}\n"

        self.log_box.config(state=tk.NORMAL)
        self.log_box.insert(tk.END, line)

        lines = self.log_box.get("1.0", tk.END).splitlines()
        if len(lines) > LOG_MAX_LINES:
            self.log_box.delete("1.0", f"{len(lines)-LOG_MAX_LINES+1}.0")

        self.log_box.see(tk.END)
        self.log_box.config(state=tk.DISABLED)

    # -------------------------
    # ESTADÍSTICAS Y RECURSOS
    # -------------------------

    def update_stats(self):
        self.stats_text.config(
            text=f"Accepted: {self.allowed_count}\nBlocked: {self.blocked_count}\nPPS: {self.current_pps}"
        )

    def update_resources(self):
        now = time.time()
        if now - self.last_resource_update >= 1.5:
            self.cpu_usage += random.randint(-3, 4)
            self.ram_usage += random.randint(-2, 3)

            self.cpu_usage = max(5, min(80, self.cpu_usage))
            self.ram_usage = max(20, min(90, self.ram_usage))

            self.resource_text.config(
                text=f"CPU: {self.cpu_usage}%\nRAM: {self.ram_usage}%"
            )

            self.last_resource_update = now

    def update_pps(self):
        now = time.time()
        elapsed = now - self.last_pps_time
        if elapsed >= 1:
            self.current_pps = self.pps_counter
            self.pps_counter = 0
            self.last_pps_time = now

    # -------------------------
    # LOOP PRINCIPAL
    # -------------------------

    def update_loop(self):
        if not self.running:
            return

        now = time.time()

        if self.attack_mode:
            if int(now * 2) % 2 == 0:
                self.canvas.itemconfig(self.attack_banner, fill="#fca5a5")
            else:
                self.canvas.itemconfig(self.attack_banner, fill="#f87171")

            if (now - self.last_spawn_time) * 1000 >= 150:
                self.spawn_packet()
                self.last_spawn_time = now

            if now >= self.attack_end_time:
                self.attack_mode = False
                self.paint_button_green("⚠ ENABLE ATTACK MODE")
                self.canvas.delete(self.attack_banner)
                self.canvas.itemconfig(self.firewall_rect, fill="#b91c1c")
                self.log_event("Modo ataque finalizado. Tráfico normal restaurado.", kind="info")

        else:
            if (now - self.last_spawn_time) * 1000 >= SPAWN_INTERVAL_MS:
                self.spawn_packet()
                self.last_spawn_time = now

        for p in list(self.packets):
            prev_result = p.result
            p.step(self.firewall_x, self.server_x)

            if p.result is not None and prev_result is None:
                if p.result == "allowed":
                    self.allowed_count += 1
                    self.log_event(f"Package {p.proto} allowed.", kind="allow")
                else:
                    self.blocked_count += 1
                    self.log_event(f"Package {p.proto} blocked.", kind="block")
                self.update_stats()

            if not p.alive:
                self.packets.remove(p)

        self.update_pps()
        self.update_stats()
        self.update_resources()

        self.root.after(30, self.update_loop)


# -----------------------------
# Main
# -----------------------------

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallSimulator(root)
    root.mainloop()
