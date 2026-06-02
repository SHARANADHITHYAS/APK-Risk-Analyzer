import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from apk_analyzer import analyze_apk, format_report


APP_BG = "#08111f"
CARD_BG = "#14233a"
ACCENT = "#36cfc9"
ACCENT_2 = "#7c5cff"
TEXT = "#e8eefc"
MUTED = "#9fb0d0"
DANGER = "#ff5c77"
SAFE = "#49d17d"
WARNING = "#f5b83d"


app = tk.Tk()
app.title("APK Risk Analyzer")
app.geometry("980x680")
app.minsize(900, 620)
app.configure(bg=APP_BG)

selected_file = tk.StringVar(master=app, value="No file selected")
status_text = tk.StringVar(master=app, value="Choose an APK file to begin analysis.")
verdict_text = tk.StringVar(master=app, value="Waiting for file")
confidence_text = tk.StringVar(master=app, value="Confidence: -")


def choose_file():
    path = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
    if path:
        selected_file.set(path)
        status_text.set("File selected. Click Analyze APK.")
        verdict_text.set("Ready to analyze")
        confidence_text.set("Confidence: -")
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, "Selected file:\n" + path)


def render_result(report):
    verdict = report["verdict"]
    if verdict == "safe":
        verdict_color = SAFE
    elif verdict == "suspicious":
        verdict_color = WARNING
    else:
        verdict_color = DANGER

    verdict_text.set(report["label"])
    confidence_text.set(f"Confidence: {report['confidence'] * 100:.1f}%")
    status_text.set(report["summary"])
    verdict_value.configure(foreground=verdict_color)

    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, format_report(report))


def analyze_selected_file():
    path = selected_file.get()
    if not path or path == "No file selected":
        messagebox.showwarning("APK Analyzer", "Please select an APK file first.")
        return

    report = analyze_apk(path)
    render_result(report)


style = ttk.Style()
style.theme_use("clam")
style.configure("TFrame", background=APP_BG)
style.configure("Card.TFrame", background=CARD_BG)
style.configure("Header.TLabel", background=APP_BG, foreground=TEXT, font=("Segoe UI", 24, "bold"))
style.configure("SubHeader.TLabel", background=APP_BG, foreground=MUTED, font=("Segoe UI", 10))
style.configure("CardTitle.TLabel", background=CARD_BG, foreground=TEXT, font=("Segoe UI", 12, "bold"))
style.configure("Body.TLabel", background=CARD_BG, foreground=MUTED, font=("Segoe UI", 10))
style.configure("Accent.TButton", font=("Segoe UI", 11, "bold"), padding=10)
style.map("Accent.TButton", background=[("active", ACCENT_2), ("!active", ACCENT)], foreground=[("!disabled", "#06101a")])

root = ttk.Frame(app, padding=24)
root.pack(fill="both", expand=True)

header = ttk.Frame(root)
header.pack(fill="x", pady=(0, 18))

ttk.Label(header, text="APK Risk Analyzer", style="Header.TLabel").pack(anchor="w")
ttk.Label(
    header,
    text="Upload an APK, run the backend check, and get a single safety verdict with reasons.",
    style="SubHeader.TLabel",
).pack(anchor="w", pady=(6, 0))

content = ttk.Frame(root)
content.pack(fill="both", expand=True)
content.columnconfigure(0, weight=1)
content.columnconfigure(1, weight=1)
content.rowconfigure(1, weight=1)

left_panel = ttk.Frame(content, style="Card.TFrame", padding=18)
left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 10))

right_panel = ttk.Frame(content, style="Card.TFrame", padding=18)
right_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=(0, 10))

ttk.Label(left_panel, text="1. Select APK", style="CardTitle.TLabel").pack(anchor="w")
ttk.Label(left_panel, textvariable=selected_file, style="Body.TLabel", wraplength=420).pack(anchor="w", pady=(10, 12))
ttk.Button(left_panel, text="Choose APK File", style="Accent.TButton", command=choose_file).pack(anchor="w")
ttk.Button(left_panel, text="Analyze APK", style="Accent.TButton", command=analyze_selected_file).pack(anchor="w", pady=(10, 0))

ttk.Separator(left_panel).pack(fill="x", pady=16)

ttk.Label(left_panel, text="Status", style="CardTitle.TLabel").pack(anchor="w")
ttk.Label(left_panel, textvariable=status_text, style="Body.TLabel", wraplength=420).pack(anchor="w", pady=(10, 0))

ttk.Label(right_panel, text="2. Verdict", style="CardTitle.TLabel").pack(anchor="w")

verdict_value = ttk.Label(right_panel, textvariable=verdict_text, background=CARD_BG, foreground=SAFE, font=("Segoe UI", 20, "bold"))
verdict_value.pack(anchor="w", pady=(12, 6))

ttk.Label(right_panel, textvariable=confidence_text, style="Body.TLabel").pack(anchor="w")

result_card = ttk.Frame(root, style="Card.TFrame", padding=18)
result_card.pack(fill="both", expand=True)

ttk.Label(result_card, text="Analysis Report", style="CardTitle.TLabel").pack(anchor="w")

output_box = tk.Text(
    result_card,
    height=16,
    wrap=tk.WORD,
    bg="#0b1324",
    fg=TEXT,
    insertbackground=TEXT,
    relief="flat",
    padx=14,
    pady=14,
    font=("Consolas", 10),
)
output_box.pack(fill="both", expand=True, pady=(12, 0))
output_box.insert(tk.END, "Select an APK to see the verdict here.")

app.mainloop()