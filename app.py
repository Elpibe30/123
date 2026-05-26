import customtkinter as ctk
from tkinter import messagebox, filedialog
import requests
import hashlib
import uuid
import platform
import os
import threading

API_URL = "http://127.0.0.1:5000/api"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PriceWiseApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("💰 PriceWise - Buscador de Precios")
        self.geometry("1200x700")
        self.minsize(900, 600)
        
        self.token = None
        self.user_id = None
        self.es_admin = False
        self.user_nombre = None
        self.device_id = self.get_device_id()
        
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True)
        
        self.show_login()
    
    def get_device_id(self):
        try:
            return hashlib.md5(f"{platform.node()}-{os.getlogin()}".encode()).hexdigest()
        except:
            return str(uuid.uuid4())
    
    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def show_login(self):
        self.clear_frame()
        
        center = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        center.pack(expand=True)
        
        ctk.CTkLabel(center, text="💰", font=("Segoe UI Emoji", 60)).pack(pady=(20, 0))
        ctk.CTkLabel(center, text="PRICEWISE", font=("Arial", 36, "bold"), text_color="#1a73e8").pack()
        ctk.CTkLabel(center, text="Buscador de Precios de Construcción", font=("Arial", 14), text_color="gray").pack(pady=(0, 30))
        
        card = ctk.CTkFrame(center, width=380, height=380, corner_radius=15)
        card.pack(pady=20)
        card.pack_propagate(False)
        
        ctk.CTkLabel(card, text="🔐 Iniciar Sesión", font=("Arial", 20, "bold")).pack(pady=(20, 15))
        
        self.login_email = ctk.CTkEntry(card, placeholder_text="Email", width=300, height=45)
        self.login_email.pack(pady=8)
        
        self.login_pass = ctk.CTkEntry(card, placeholder_text="Contraseña", show="*", width=300, height=45)
        self.login_pass.pack(pady=8)
        
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(pady=25)
        
        self.login_btn = ctk.CTkButton(btn_frame, text="Ingresar", command=self.do_login, width=130, height=45, fg_color="#1a73e8")
        self.login_btn.pack(side="left", padx=10)
        
        self.register_btn = ctk.CTkButton(btn_frame, text="Registrarse", command=self.show_register, width=130, height=45, fg_color="#00c853")
        self.register_btn.pack(side="left", padx=10)
    
    def show_register(self):
        self.clear_frame()
        
        center = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        center.pack(expand=True)
        
        ctk.CTkLabel(center, text="💰 PRICEWISE", font=("Arial", 28, "bold"), text_color="#1a73e8").pack(pady=(20, 5))
        ctk.CTkLabel(center, text="Crear una cuenta nueva", font=("Arial", 14), text_color="gray").pack(pady=(0, 20))
        
        card = ctk.CTkFrame(center, width=380, height=500, corner_radius=15)
        card.pack()
        card.pack_propagate(False)
        
        ctk.CTkLabel(card, text="📝 Registro", font=("Arial", 18, "bold")).pack(pady=(20, 15))
        
        self.reg_nombre = ctk.CTkEntry(card, placeholder_text="Nombre completo", width=300, height=45)
        self.reg_nombre.pack(pady=8)
        
        self.reg_email = ctk.CTkEntry(card, placeholder_text="Email", width=300, height=45)
        self.reg_email.pack(pady=8)
        
        self.reg_pass = ctk.CTkEntry(card, placeholder_text="Contraseña (mínimo 4 caracteres)", show="*", width=300, height=45)
        self.reg_pass.pack(pady=8)
        
        self.reg_pass2 = ctk.CTkEntry(card, placeholder_text="Confirmar contraseña", show="*", width=300, height=45)
        self.reg_pass2.pack(pady=8)
        
        ctk.CTkButton(card, text="Crear cuenta", command=self.do_register, width=200, height=45, fg_color="#00c853").pack(pady=15)
        ctk.CTkButton(card, text="← Volver al inicio", command=self.show_login, width=200, height=35, fg_color="#555555").pack(pady=5)
    
    def do_login(self):
        email = self.login_email.get()
        password = self.login_pass.get()
        
        if not email or not password:
            messagebox.showerror("Error", "Completa todos los campos")
            return
        
        self.login_btn.configure(state="disabled", text="Cargando...")
        
        def login_thread():
            try:
                r = requests.post(f"{API_URL}/login", json={
                    'email': email,
                    'password': password,
                    'device_id': self.device_id
                }, timeout=10)
                
                if r.status_code == 200:
                    data = r.json()
                    self.token = data['token']
                    self.user_id = data['user_id']
                    self.es_admin = data.get('es_admin', False)
                    self.user_nombre = data.get('nombre', email)
                    self.after(0, self.show_main_app)
                else:
                    error = r.json().get('error', 'Credenciales incorrectas')
                    self.after(0, lambda: messagebox.showerror("Error", error))
                    self.after(0, lambda: self.login_btn.configure(state="normal", text="Ingresar"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", f"Error: {str(e)}\n\n¿El servidor está corriendo?"))
                self.after(0, lambda: self.login_btn.configure(state="normal", text="Ingresar"))
        
        threading.Thread(target=login_thread).start()
    
    def do_register(self):
        if self.reg_pass.get() != self.reg_pass2.get():
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return
        
        if len(self.reg_pass.get()) < 4:
            messagebox.showerror("Error", "La contraseña debe tener al menos 4 caracteres")
            return
        
        self.register_btn.configure(state="disabled", text="Registrando...")
        
        def register_thread():
            try:
                r = requests.post(f"{API_URL}/register", json={
                    'nombre': self.reg_nombre.get(),
                    'email': self.reg_email.get(),
                    'password': self.reg_pass.get(),
                    'device_id': self.device_id
                }, timeout=10)
                
                if r.status_code == 201:
                    self.after(0, lambda: messagebox.showinfo("Éxito", "✅ Registro exitoso! Tienes 45 días gratis."))
                    self.after(0, self.show_login)
                else:
                    error = r.json().get('error', 'Error al registrar')
                    self.after(0, lambda: messagebox.showerror("Error", error))
                self.after(0, lambda: self.register_btn.configure(state="normal", text="Crear cuenta"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", f"Error: {str(e)}"))
                self.after(0, lambda: self.register_btn.configure(state="normal", text="Crear cuenta"))
        
        threading.Thread(target=register_thread).start()
    
    def show_main_app(self):
        self.clear_frame()
        
        top_bar = ctk.CTkFrame(self.main_frame, height=60, corner_radius=0)
        top_bar.pack(fill="x", side="top")
        top_bar.pack_propagate(False)
        
        ctk.CTkLabel(top_bar, text="💰", font=("Segoe UI Emoji", 30)).pack(side="left", padx=(15, 5))
        ctk.CTkLabel(top_bar, text="PRICEWISE", font=("Arial", 22, "bold"), text_color="#1a73e8").pack(side="left")
        ctk.CTkLabel(top_bar, text="Buscador de Precios", font=("Arial", 12), text_color="gray").pack(side="left", padx=5)
        
        user_frame = ctk.CTkFrame(top_bar, fg_color="transparent")
        user_frame.pack(side="right", padx=15)
        
        ctk.CTkLabel(user_frame, text=f"👤 {self.user_nombre}", font=("Arial", 12)).pack(side="left", padx=10)
        
        if self.es_admin:
            admin_btn = ctk.CTkButton(user_frame, text="📤 Subir Excel", command=self.subir_excel, width=110, height=35, fg_color="#ff8c00")
            admin_btn.pack(side="left", padx=5)
        
        logout_btn = ctk.CTkButton(user_frame, text="Salir", command=self.show_login, width=80, height=35, fg_color="#d32f2f")
        logout_btn.pack(side="left", padx=5)
        
        search_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        search_frame.pack(fill="x", padx=30, pady=25)
        
        ctk.CTkLabel(search_frame, text="🔍 Buscar en todo el catálogo", font=("Arial", 18, "bold")).pack(anchor="w", pady=(0, 10))
        
        search_container = ctk.CTkFrame(search_frame, fg_color="transparent")
        search_container.pack(fill="x")
        
        self.search_entry = ctk.CTkEntry(search_container, placeholder_text="Ej: cemento, mano de obra, empresa, teléfono, dirección...", height=50, font=("Arial", 14))
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.search_entry.bind("<Return>", self.buscar)
        
        self.buscar_btn = ctk.CTkButton(search_container, text="Buscar", command=self.buscar, width=130, height=50, fg_color="#1a73e8")
        self.buscar_btn.pack(side="right")
        
        self.result_count_label = ctk.CTkLabel(search_frame, text="", font=("Arial", 12), text_color="gray")
        self.result_count_label.pack(anchor="w", pady=(10, 0))
        
        self.result_text = ctk.CTkTextbox(self.main_frame, font=("Consolas", 11))
        self.result_text.pack(fill="both", expand=True, padx=30, pady=(0, 25))
        
        self.buscar()
    
    def buscar(self, event=None):
        termino = self.search_entry.get().strip()
        
        self.buscar_btn.configure(state="disabled", text="Buscando...")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", "🔄 Cargando...")
        
        def buscar_thread():
            try:
                headers = {'Authorization': self.token}
                url = f"{API_URL}/buscar"
                if termino:
                    url += f"?q={termino}"
                
                r = requests.get(url, headers=headers, timeout=15)
                
                if r.status_code == 200:
                    resultados = r.json()
                    self.after(0, lambda: self.mostrar_resultados(resultados))
                else:
                    self.after(0, lambda: self.result_text.delete("1.0", "end"))
                    self.after(0, lambda: self.result_text.insert("1.0", "❌ Error al cargar datos"))
                self.after(0, lambda: self.buscar_btn.configure(state="normal", text="Buscar"))
            except Exception as e:
                self.after(0, lambda: self.result_text.delete("1.0", "end"))
                self.after(0, lambda: self.result_text.insert("1.0", f"❌ Error: {str(e)}"))
                self.after(0, lambda: self.buscar_btn.configure(state="normal", text="Buscar"))
        
        threading.Thread(target=buscar_thread).start()
    
    def mostrar_resultados(self, resultados):
        self.result_text.delete("1.0", "end")
        
        if not resultados:
            self.result_text.insert("1.0", "😕 No se encontraron resultados\n\nSugerencias:\n• Prueba con otras palabras\n• Revisa que hayas subido el Excel\n• Busca: cemento, empresa, mano de obra")
            self.result_count_label.configure(text="0 resultados")
            return
        
        for r in resultados:
            texto = r.get('texto', '')
            tipo = r.get('tipo', 'producto')
            precio = r.get('precio', 0)
            unidad = r.get('unidad', '')
            fila = r.get('fila_original', '')
            
            if tipo == 'empresa':
                icono = "🏢"
            else:
                icono = "📌"
            
            self.result_text.insert("end", f"{icono} {texto}\n")
            if unidad:
                self.result_text.insert("end", f"   Unidad: {unidad}\n")
            if precio > 0:
                self.result_text.insert("end", f"   Precio: Bs {precio:,.2f}\n")
            if fila:
                self.result_text.insert("end", f"   {fila[:300]}\n")
            self.result_text.insert("end", "-" * 80 + "\n")
        
        self.result_count_label.configure(text=f"📊 {len(resultados)} resultados encontrados")
    
    def subir_excel(self):
        if not self.es_admin:
            messagebox.showerror("Error", "No tienes permisos de administrador")
            return
        
        filepath = filedialog.askopenfilename(
            title="Seleccionar archivo Excel",
            filetypes=[("Excel files", "*.xlsx"), ("Todos los archivos", "*.*")]
        )
        
        if not filepath:
            return
        
        if not messagebox.askyesno("Confirmar", "📤 ¿Subir este archivo?\n\nSe actualizará todo el catálogo."):
            return
        
        try:
            with open(filepath, 'rb') as f:
                r = requests.post(f"{API_URL}/sincronizar", headers={'Authorization': self.token}, files={'file': f}, timeout=60)
                if r.status_code == 200:
                    data = r.json()
                    messagebox.showinfo("Éxito", data.get('message', 'Datos sincronizados'))
                    self.buscar()
                else:
                    messagebox.showerror("Error", r.json().get('error'))
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")

if __name__ == "__main__":
    app = PriceWiseApp()
    app.mainloop()
    