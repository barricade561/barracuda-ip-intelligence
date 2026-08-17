"""Simple Tkinter desktop interface suitable for PyInstaller packaging."""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from .engine import Analyzer
from .reporting import write_csv, write_json


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Barracuda IP Intelligence")
        self.geometry("900x650")
        self.minsize(720, 480)
        self.report: dict[str, Any] | None = None
        self.result_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._build()

    def _build(self) -> None:
        frame = ttk.Frame(self, padding=14)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="IP address / IP adresi:").grid(row=0, column=0, sticky="w")
        self.ip_var = tk.StringVar(value="8.8.8.8")
        entry = ttk.Entry(frame, textvariable=self.ip_var, width=45)
        entry.grid(row=0, column=1, sticky="ew", padx=8)
        entry.bind("<Return>", lambda _event: self.start_analysis())
        self.analyze_button = ttk.Button(frame, text="Analyze / Analiz Et", command=self.start_analysis)
        self.analyze_button.grid(row=0, column=2)

        self.keyless_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            frame,
            text="Use keyless public sources / Anahtarsız açık kaynakları kullan",
            variable=self.keyless_var,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 4))

        provider_frame = ttk.LabelFrame(frame, text="Optional providers / Opsiyonel sağlayıcılar", padding=8)
        provider_frame.grid(row=2, column=0, columnspan=3, sticky="ew")
        self.provider_vars: dict[str, tk.BooleanVar] = {}
        for column, name in enumerate(("abuseipdb", "virustotal", "shodan", "greynoise")):
            variable = tk.BooleanVar(value=True)
            self.provider_vars[name] = variable
            ttk.Checkbutton(provider_frame, text=name, variable=variable).grid(row=0, column=column, padx=8)

        self.status_var = tk.StringVar(value="Ready / Hazır")
        ttk.Label(frame, textvariable=self.status_var).grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 4))

        self.output = tk.Text(frame, wrap="word", font=("Consolas", 10))
        self.output.grid(row=4, column=0, columnspan=3, sticky="nsew")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.output.yview)
        scrollbar.grid(row=4, column=3, sticky="ns")
        self.output.configure(yscrollcommand=scrollbar.set)

        buttons = ttk.Frame(frame)
        buttons.grid(row=5, column=0, columnspan=3, sticky="e", pady=(10, 0))
        ttk.Button(buttons, text="Save JSON", command=self.save_json).pack(side="left", padx=4)
        ttk.Button(buttons, text="Save CSV", command=self.save_csv).pack(side="left", padx=4)

        notice = "Passive sources only. Geolocation is approximate. / Yalnızca pasif kaynaklar. Konum yaklaşık değerdir."
        ttk.Label(frame, text=notice, foreground="#7a4d00").grid(row=6, column=0, columnspan=3, sticky="w", pady=(8, 0))
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
        entry.focus_set()

    def start_analysis(self) -> None:
        ip = self.ip_var.get().strip()
        if not ip:
            messagebox.showwarning("Missing IP", "Enter an IPv4 or IPv6 address.")
            return
        selected = {name for name, variable in self.provider_vars.items() if variable.get()}
        self.analyze_button.configure(state="disabled")
        self.status_var.set("Analyzing passive sources... / Pasif kaynaklar analiz ediliyor...")
        self.output.delete("1.0", "end")

        def worker() -> None:
            try:
                result = Analyzer().analyze(ip, use_keyless=self.keyless_var.get(), provider_names=selected)
                self.result_queue.put(("ok", result))
            except Exception as exc:
                self.result_queue.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, self._poll)

    def _poll(self) -> None:
        try:
            status, payload = self.result_queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll)
            return
        self.analyze_button.configure(state="normal")
        if status == "error":
            self.status_var.set("Analysis failed / Analiz başarısız")
            messagebox.showerror("Analysis error", str(payload))
            return
        self.report = payload
        risk = self.report["risk"]
        self.status_var.set(f"Risk: {risk['score']}/100 - {risk['level'].upper()} | Evidence: {risk['provider_count']}")
        self.output.insert("1.0", json.dumps(self.report, indent=2, ensure_ascii=False))

    def save_json(self) -> None:
        self._save("json")

    def save_csv(self) -> None:
        self._save("csv")

    def _save(self, kind: str) -> None:
        if not self.report:
            messagebox.showinfo("No report", "Run an analysis first. / Önce analiz çalıştırın.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=f".{kind}",
            initialfile=f"ip-report-{self.report['target'].replace(':', '_')}.{kind}",
            filetypes=[(kind.upper(), f"*.{kind}"), ("All files", "*.*")],
        )
        if not path:
            return
        output = write_json(self.report, Path(path)) if kind == "json" else write_csv(self.report, Path(path))
        messagebox.showinfo("Saved", f"Saved to / Kaydedildi:\n{output}")


def main() -> None:
    App().mainloop()


if __name__ == "__main__":
    main()


