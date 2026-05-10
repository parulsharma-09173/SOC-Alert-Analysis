import os
import re
import csv
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime, timedelta
from collections import defaultdict

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


def analyze_auth_log(log_file, output_dir, geoip_db_file=None):
    os.makedirs(output_dir, exist_ok=True)

    blacklist_file = os.path.join(output_dir, "blacklist.txt")
    csv_file = os.path.join(output_dir, "report.csv")
    alerts_file = os.path.join(output_dir, "alerts.txt")
    chart_failed_attempts = os.path.join(output_dir, "failed_attempts_by_ip.png")
    chart_risk_score = os.path.join(output_dir, "risk_score_by_ip.png")
    chart_username_enum = os.path.join(output_dir, "username_enumeration_by_ip.png")

    failed_attempts = defaultdict(int)
    failed_timestamps = defaultdict(list)
    successful_logins = defaultdict(list)
    usernames_by_ip = defaultdict(set)
    ips_by_username = defaultdict(set)
    invalid_usernames_by_ip = defaultdict(set)
    alerts = set()

    ip_pattern = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
    timestamp_pattern = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})')
    failed_invalid_user_pattern = re.compile(r'Failed password for invalid user\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})')
    failed_valid_user_pattern = re.compile(r'Failed password for\s+(?!invalid user)(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})')
    accepted_user_pattern = re.compile(r'Accepted password for\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})')

    current_year = datetime.now().year

    def parse_timestamp(line):
        match = timestamp_pattern.search(line)
        if match:
            try:
                return datetime.strptime(f"{current_year} {match.group(1)}", "%Y %b %d %H:%M:%S")
            except ValueError:
                return None
        return None

    def classify_risk(score):
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"

    geoip_reader = None
    if geoip_db_file and GEOIP_AVAILABLE and os.path.exists(geoip_db_file):
        geoip_reader = geoip2.database.Reader(geoip_db_file)
    else:
        alerts.add("[INFO] GeoIP database not loaded. Impossible travel country detection will be limited.")

    def get_country(ip):
        if not geoip_reader:
            return "Unknown"
        try:
            response = geoip_reader.city(ip)
            return response.country.name or "Unknown"
        except Exception:
            return "Unknown"

    with open(log_file, "r", encoding="utf-8", errors="ignore") as file:
        for raw_line in file:
            line = raw_line.strip()
            if not line:
                continue

            timestamp = parse_timestamp(line)
            failed_invalid_match = failed_invalid_user_pattern.search(line)
            failed_valid_match = failed_valid_user_pattern.search(line)
            accepted_match = accepted_user_pattern.search(line)

            if failed_invalid_match:
                username, ip = failed_invalid_match.groups()
                failed_attempts[ip] += 1
                usernames_by_ip[ip].add(username)
                invalid_usernames_by_ip[ip].add(username)
                ips_by_username[username].add(ip)
                if timestamp:
                    failed_timestamps[ip].append(timestamp)
                alerts.add(f"[MEDIUM] Invalid user attempt: username={username}, ip={ip}")

            elif failed_valid_match:
                username, ip = failed_valid_match.groups()
                failed_attempts[ip] += 1
                usernames_by_ip[ip].add(username)
                ips_by_username[username].add(ip)
                if timestamp:
                    failed_timestamps[ip].append(timestamp)

            elif accepted_match:
                username, ip = accepted_match.groups()
                country = get_country(ip)
                successful_logins[ip].append((timestamp, username, country))
                usernames_by_ip[ip].add(username)
                ips_by_username[username].add(ip)

            else:
                ip_match = ip_pattern.search(line)
                if not ip_match:
                    continue
                ip = ip_match.group()
                if "Failed password" in line:
                    failed_attempts[ip] += 1
                    if timestamp:
                        failed_timestamps[ip].append(timestamp)
                elif "Accepted password" in line:
                    successful_logins[ip].append((timestamp, "Unknown", get_country(ip)))

    impossible_travel_users = set()
    user_success_events = defaultdict(list)
    for ip, events in successful_logins.items():
        for timestamp, username, country in events:
            if timestamp and username != "Unknown":
                user_success_events[username].append((timestamp, ip, country))

    for username, events in user_success_events.items():
        events = sorted(events, key=lambda x: x[0])
        for i in range(len(events) - 1):
            t1, ip1, country1 = events[i]
            t2, ip2, country2 = events[i + 1]
            if country1 != "Unknown" and country2 != "Unknown" and country1 != country2 and t2 - t1 <= timedelta(hours=2):
                impossible_travel_users.add(username)
                alerts.add(f"[CRITICAL] Impossible travel: user={username}, {country1}({ip1}) -> {country2}({ip2}) within 2 hours")

    blacklisted_ips = []
    report_rows = []
    all_ips = set(failed_attempts.keys()) | set(successful_logins.keys()) | set(usernames_by_ip.keys())

    for ip in sorted(all_ips):
        count = failed_attempts.get(ip, 0)
        brute_force = "NO"
        irregular_pattern = "NO"
        username_enumeration = "NO"
        suspicious_success = "NO"
        impossible_travel = "NO"
        risk_score = 0
        notes = []

        if count >= 3:
            brute_force = "YES"
            risk_score += 40
            blacklisted_ips.append(ip)
            notes.append("Repeated failed logins")
            alerts.add(f"[HIGH] Brute force detected from {ip} ({count} attempts)")

        if len(failed_timestamps[ip]) >= 3:
            times = sorted(failed_timestamps[ip])
            for i in range(len(times) - 2):
                if times[i + 2] - times[i] <= timedelta(minutes=2):
                    irregular_pattern = "YES"
                    risk_score += 30
                    if ip not in blacklisted_ips:
                        blacklisted_ips.append(ip)
                    notes.append("Rapid failures in short time window")
                    alerts.add(f"[HIGH] Rapid failed logins from {ip} (3+ attempts within 2 minutes)")
                    break

        attempted_user_count = len(usernames_by_ip[ip])
        invalid_user_count = len(invalid_usernames_by_ip[ip])
        if attempted_user_count >= 5 or invalid_user_count >= 3:
            username_enumeration = "YES"
            risk_score += 30
            if ip not in blacklisted_ips:
                blacklisted_ips.append(ip)
            notes.append("Username enumeration")
            alerts.add(f"[HIGH] Username enumeration from {ip}: {attempted_user_count} usernames, {invalid_user_count} invalid usernames")

        if ip in successful_logins and ip in failed_timestamps:
            fail_times = sorted(failed_timestamps[ip])
            success_times = sorted([event[0] for event in successful_logins[ip] if event[0]])
            for success_time in success_times:
                recent_failures = sum(1 for fail_time in fail_times if fail_time <= success_time and success_time - fail_time <= timedelta(minutes=5))
                if recent_failures >= 3:
                    suspicious_success = "YES"
                    irregular_pattern = "YES"
                    risk_score += 25
                    notes.append("Successful login after repeated failures")
                    alerts.add(f"[HIGH] Suspicious login success from {ip} after multiple failures")
                    break

        ip_success_users = {username for _, username, _ in successful_logins.get(ip, [])}
        if ip_success_users & impossible_travel_users:
            impossible_travel = "YES"
            risk_score += 40
            if ip not in blacklisted_ips:
                blacklisted_ips.append(ip)
            notes.append("Impossible travel detected for user")

        if invalid_user_count > 0:
            risk_score += 10
        if count >= 10:
            risk_score += 20

        risk_score = min(risk_score, 100)
        report_rows.append({
            "IP": ip,
            "Failed_Attempts": count,
            "Unique_Usernames": attempted_user_count,
            "Invalid_Usernames": invalid_user_count,
            "Brute_Force": brute_force,
            "Irregular_Pattern": irregular_pattern,
            "Username_Enumeration": username_enumeration,
            "Suspicious_Success": suspicious_success,
            "Impossible_Travel": impossible_travel,
            "Risk_Score": risk_score,
            "Risk_Level": classify_risk(risk_score),
            "Notes": "; ".join(notes) if notes else "None"
        })

    with open(blacklist_file, "w", encoding="utf-8") as f:
        for ip in sorted(set(blacklisted_ips)):
            f.write(ip + "\n")

    fieldnames = ["IP", "Failed_Attempts", "Unique_Usernames", "Invalid_Usernames", "Brute_Force", "Irregular_Pattern", "Username_Enumeration", "Suspicious_Success", "Impossible_Travel", "Risk_Score", "Risk_Level", "Notes"]
    with open(csv_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_rows)

    with open(alerts_file, "w", encoding="utf-8") as f:
        for alert in sorted(alerts):
            f.write(alert + "\n")

    chart_files = []
    if MATPLOTLIB_AVAILABLE and report_rows:
        def save_bar_chart(rows, x_key, y_key, title, ylabel, output_file):
            labels = [row[x_key] for row in rows]
            values = [row[y_key] for row in rows]
            plt.figure(figsize=(10, 6))
            plt.bar(labels, values)
            plt.title(title)
            plt.xlabel(x_key)
            plt.ylabel(ylabel)
            plt.xticks(rotation=45, ha="right")
            plt.tight_layout()
            plt.savefig(output_file)
            plt.close()
            chart_files.append(output_file)

        save_bar_chart(sorted(report_rows, key=lambda x: x["Failed_Attempts"], reverse=True)[:10], "IP", "Failed_Attempts", "Top Failed Login Attempts by IP", "Failed Attempts", chart_failed_attempts)
        save_bar_chart(sorted(report_rows, key=lambda x: x["Risk_Score"], reverse=True)[:10], "IP", "Risk_Score", "Top Risk Scores by IP", "Risk Score", chart_risk_score)
        save_bar_chart(sorted(report_rows, key=lambda x: x["Unique_Usernames"], reverse=True)[:10], "IP", "Unique_Usernames", "Username Enumeration by IP", "Unique Usernames", chart_username_enum)

    if geoip_reader:
        geoip_reader.close()

    return {
        "alerts": sorted(alerts),
        "rows": report_rows,
        "blacklist_file": blacklist_file,
        "csv_file": csv_file,
        "alerts_file": alerts_file,
        "chart_files": chart_files,
        "output_dir": output_dir
    }


class AuthAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SOC Auth Log Analyzer")
        self.root.geometry("1150x750")

        self.log_path = tk.StringVar()
        self.output_dir = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Downloads"))
        self.geoip_path = tk.StringVar()
        self.status = tk.StringVar(value="Select an auth.log file and click Run Analysis.")
        self.chart_images = []

        self.build_ui()

    def build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Auth Log File:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.log_path, width=80).grid(row=0, column=1, padx=5)
        ttk.Button(top, text="Browse", command=self.browse_log).grid(row=0, column=2)

        ttk.Label(top, text="Output Folder:").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(top, textvariable=self.output_dir, width=80).grid(row=1, column=1, padx=5)
        ttk.Button(top, text="Browse", command=self.browse_output).grid(row=1, column=2)

        ttk.Label(top, text="GeoIP DB Optional:").grid(row=2, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.geoip_path, width=80).grid(row=2, column=1, padx=5)
        ttk.Button(top, text="Browse", command=self.browse_geoip).grid(row=2, column=2)

        ttk.Button(top, text="Run Analysis", command=self.run_analysis_thread).grid(row=3, column=1, sticky="w", pady=10)
        ttk.Label(top, textvariable=self.status).grid(row=3, column=1, sticky="e")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.summary_tab = ttk.Frame(self.notebook)
        self.alerts_tab = ttk.Frame(self.notebook)
        self.blacklist_tab = ttk.Frame(self.notebook)
        self.charts_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.summary_tab, text="Summary")
        self.notebook.add(self.alerts_tab, text="Alerts")
        self.notebook.add(self.blacklist_tab, text="Blacklist")
        self.notebook.add(self.charts_tab, text="Charts")

        columns = ("IP", "Failed_Attempts", "Unique_Usernames", "Invalid_Usernames", "Brute_Force", "Username_Enumeration", "Suspicious_Success", "Impossible_Travel", "Risk_Score", "Risk_Level", "Notes")
        self.tree = ttk.Treeview(self.summary_tab, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor="center")
        self.tree.column("Notes", width=300, anchor="w")
        self.tree.pack(fill="both", expand=True)

        self.alert_text = tk.Text(self.alerts_tab, wrap="word")
        self.alert_text.pack(fill="both", expand=True)

        self.blacklist_text = tk.Text(self.blacklist_tab, wrap="word")
        self.blacklist_text.pack(fill="both", expand=True)

        self.chart_frame = ttk.Frame(self.charts_tab)
        self.chart_frame.pack(fill="both", expand=True)

    def browse_log(self):
        path = filedialog.askopenfilename(title="Select auth.log", filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")])
        if path:
            self.log_path.set(path)

    def browse_output(self):
        path = filedialog.askdirectory(title="Select output folder")
        if path:
            self.output_dir.set(path)

    def browse_geoip(self):
        path = filedialog.askopenfilename(title="Select GeoLite2-City.mmdb", filetypes=[("MaxMind DB", "*.mmdb"), ("All files", "*.*")])
        if path:
            self.geoip_path.set(path)

    def run_analysis_thread(self):
        if not self.log_path.get() or not os.path.exists(self.log_path.get()):
            messagebox.showerror("Missing file", "Please select a valid auth.log file.")
            return
        self.status.set("Running analysis...")
        threading.Thread(target=self.run_analysis, daemon=True).start()

    def run_analysis(self):
        try:
            geoip = self.geoip_path.get() if self.geoip_path.get() else None
            result = analyze_auth_log(self.log_path.get(), self.output_dir.get(), geoip)
            self.root.after(0, lambda: self.display_results(result))
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("Analysis failed", str(exc)))
            self.root.after(0, lambda: self.status.set("Analysis failed."))

    def display_results(self, result):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for row in sorted(result["rows"], key=lambda x: x["Risk_Score"], reverse=True):
            self.tree.insert("", "end", values=(row["IP"], row["Failed_Attempts"], row["Unique_Usernames"], row["Invalid_Usernames"], row["Brute_Force"], row["Username_Enumeration"], row["Suspicious_Success"], row["Impossible_Travel"], row["Risk_Score"], row["Risk_Level"], row["Notes"]))

        self.alert_text.delete("1.0", "end")
        self.alert_text.insert("end", "\n".join(result["alerts"]))

        self.blacklist_text.delete("1.0", "end")
        if os.path.exists(result["blacklist_file"]):
            with open(result["blacklist_file"], "r", encoding="utf-8") as f:
                self.blacklist_text.insert("end", f.read())

        for widget in self.chart_frame.winfo_children():
            widget.destroy()
        self.chart_images.clear()

        if not result["chart_files"]:
            ttk.Label(self.chart_frame, text="Charts were not generated. Install matplotlib: pip install matplotlib").pack(pady=20)
        elif PIL_AVAILABLE:
            for chart in result["chart_files"]:
                frame = ttk.LabelFrame(self.chart_frame, text=os.path.basename(chart), padding=10)
                frame.pack(fill="x", padx=10, pady=10)
                img = Image.open(chart)
                img.thumbnail((700, 350))
                photo = ImageTk.PhotoImage(img)
                self.chart_images.append(photo)
                ttk.Label(frame, image=photo).pack()
        else:
            for chart in result["chart_files"]:
                ttk.Label(self.chart_frame, text=chart).pack(anchor="w", padx=10, pady=5)
            ttk.Label(self.chart_frame, text="Install Pillow to preview charts inside the GUI: pip install pillow").pack(pady=20)

        self.status.set(f"Done. Outputs saved to: {result['output_dir']}")
        messagebox.showinfo("Analysis complete", f"Report saved to:\n{result['csv_file']}\n\nAlerts saved to:\n{result['alerts_file']}")


if __name__ == "__main__":
    root = tk.Tk()
    app = AuthAnalyzerGUI(root)
    root.mainloop()
